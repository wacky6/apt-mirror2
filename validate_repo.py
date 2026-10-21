#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validate that APT repositories configured in a sources.list / mirror.list
are valid and self-consistent (Release/InRelease, package indexes, and pool packages).
"""

import argparse
import asyncio
import bz2
import contextlib
import gzip
import logging
import lzma
import shutil
import sys
from collections.abc import AsyncIterator, Callable, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory

from debian.deb822 import Release

from apt_mirror.aiofile import BaseAsyncIOFileWriterFactory
from apt_mirror.config import Config
from apt_mirror.download import (
    Downloader,
    DownloaderFactory,
    DownloadFile,
    FileCompression,
    HashType,
)
from apt_mirror.download.downloader import DownloaderSettings
from apt_mirror.download.response import DownloadResponse
from apt_mirror.logs import LoggerFactory
from apt_mirror.repository import (
    BaseRepository,
    BaseRepositoryMetadata,
    FlatRepository,
    GPGVerify,
    InvalidSignatureError,
    PackagesParser,
    Repository,
    SourcesParser,
    is_safe_path,
    should_ignore_errors,
)

HASH_PRIORITY: tuple[HashType, ...] = (
    HashType.SHA512,
    HashType.SHA256,
    HashType.SHA1,
    HashType.MD5,
)

COMPRESSION_OPENERS: dict[FileCompression, Callable[..., Iterable[bytes]]] = {
    FileCompression.XZ: lzma.open,
    FileCompression.GZ: gzip.open,
    FileCompression.BZ2: bz2.open,
}


class IssueType(Enum):
    MISSING = "MISSING"
    HASH_MISMATCH = "HASH_MISMATCH"


@dataclass(frozen=True)
class ValidationIssue:
    issue_type: IssueType
    url: str
    detail: str | None = None

    def format_line(self) -> str:
        if self.detail:
            return f"{self.issue_type.value} {self.url} ({self.detail})"
        return f"{self.issue_type.value} {self.url}"


@dataclass
class ExpectedFile:
    path: Path
    sizes: set[int] = field(default_factory=set)
    hashes: dict[HashType, set[str]] = field(default_factory=dict)
    ignore_errors: bool = False

    def add_expectation(
        self,
        size: int | None,
        hashes: Mapping[HashType, str],
    ) -> None:
        if size is not None and size >= 0:
            self.sizes.add(size)
        for hash_type, digest in hashes.items():
            self.hashes.setdefault(hash_type, set()).add(digest.lower())

    def verify(
        self,
        url: str,
        actual_size: int,
        actual_hashes: Mapping[HashType, str],
        enabled_hashes: set[HashType],
    ) -> ValidationIssue | None:
        for hash_type in HASH_PRIORITY:
            if hash_type not in self.hashes:
                continue
            if enabled_hashes and hash_type not in enabled_hashes:
                continue

            actual_digest = actual_hashes.get(hash_type, "").lower()
            for expected_digest in sorted(self.hashes[hash_type]):
                if actual_digest != expected_digest:
                    return ValidationIssue(
                        issue_type=IssueType.HASH_MISMATCH,
                        url=url,
                        detail=(
                            f"{hash_type.value}: expected {expected_digest}, "
                            f"got {actual_digest}"
                        ),
                    )

        for expected_size in sorted(self.sizes):
            if actual_size != expected_size:
                return ValidationIssue(
                    issue_type=IssueType.HASH_MISMATCH,
                    url=url,
                    detail=f"size: expected {expected_size}, got {actual_size}",
                )

        return None


@dataclass
class FetchResult:
    found: bool
    size: int = 0
    hashes: dict[HashType, str] = field(default_factory=dict)
    error: str | None = None


class _DummyAIOFileWriterFactory(BaseAsyncIOFileWriterFactory):
    @asynccontextmanager
    async def open(self, path: Path):
        with open(path, "wb") as fp:
            yield fp

    async def test_storage(self, *test_paths: Path) -> None:
        return None


class FileDownloader(Downloader):
    """Downloader implementation for local file:// repository URLs."""

    def _iter_file(self, full_path: Path) -> Callable[[], AsyncIterator[bytes]]:
        async def _stream() -> AsyncIterator[bytes]:
            with open(full_path, "rb") as fp:
                while chunk := fp.read(self.STREAM_CHUNK_SIZE):
                    yield chunk

        return _stream

    @asynccontextmanager
    async def stream(self, source_path: Path):
        full_path = Path(self._settings.url.path) / source_path
        if not full_path.is_file():
            yield DownloadResponse(_stream=None, missing=True)
            return

        try:
            stat = full_path.stat()
            yield DownloadResponse(
                _stream=self._iter_file(full_path),
                missing=False,
                size=stat.st_size,
            )
        except OSError as ex:
            yield DownloadResponse(_stream=None, error=str(ex))


def create_downloader(
    repository: BaseRepository,
    config: Config,
    target_root: Path,
    concurrency: int,
    disable_http2: bool = False,
) -> Downloader:
    settings = DownloaderSettings(
        url=repository.url,
        target_root_path=target_root,
        aiofile_factory=_DummyAIOFileWriterFactory(),
        proxy=config.proxy,
        http2_disable=repository.http2_disable or disable_http2,
        user_agent=config.user_agent,
        semaphore=asyncio.Semaphore(concurrency),
        slow_rate_protector_factory=config.slow_rate_protector_factory,
        check_hashes=config.check_hashes,
        rate_limiter=None,
        verify_ca_certificate=config.verify_ca_certificate,
        client_certificate=config.client_certificate,
        client_private_key=config.client_private_key,
        check_local_hash=False,
        description=str(repository),
    )
    if repository.url.scheme == "file":
        return FileDownloader(settings=settings)
    return DownloaderFactory.for_settings(settings=settings)


class _PoolCollectorDict(dict[Path, DownloadFile]):
    """Intercepts DownloadFile assignments from IndexFileParser to preserve all
    expected sizes and hashes across stanzas referencing the same package path.
    """

    def __init__(self, expected_files: dict[Path, ExpectedFile]) -> None:
        super().__init__()
        self._expected_files = expected_files

    def __setitem__(self, key: Path, value: DownloadFile) -> None:
        super().__setitem__(key, value)
        expected = self._expected_files.setdefault(
            key,
            ExpectedFile(path=key, ignore_errors=value.ignore_errors),
        )
        for variant in value.iter_variants():
            expected.add_expectation(
                size=variant.size,
                hashes={ht: hs.hash for ht, hs in variant.hashes.items()},
            )


def _detect_compression(path: Path) -> FileCompression:
    suffix = path.suffix.lower()
    for compression in FileCompression:
        if compression.file_extension.lower() == suffix:
            return compression
    return FileCompression.NONE


def _decompress_and_hash(
    compressed_file: Path,
    compression: FileCompression,
    target_uncompressed_file: Path | None,
    hash_types: Iterable[HashType],
) -> tuple[int, dict[HashType, str]]:
    opener = COMPRESSION_OPENERS[compression]
    hashers = {ht: ht.get_hash_function()() for ht in hash_types}
    size = 0

    if target_uncompressed_file is not None:
        target_uncompressed_file.parent.mkdir(parents=True, exist_ok=True)

    with contextlib.ExitStack() as stack:
        src_fp = stack.enter_context(opener(compressed_file, "rb"))
        dst_fp = (
            stack.enter_context(open(target_uncompressed_file, "wb"))
            if target_uncompressed_file is not None
            else None
        )
        while chunk := src_fp.read(Downloader.HASH_READ_SIZE):  # type: ignore[attr-defined]
            size += len(chunk)
            for hasher in hashers.values():
                hasher.update(chunk)
            if dst_fp is not None:
                dst_fp.write(chunk)

    return size, {ht: h.hexdigest().lower() for ht, h in hashers.items()}


@dataclass
class _RepoMetadataState:
    groups: dict[Path, dict[FileCompression, ExpectedFile]] = field(
        default_factory=dict
    )
    known_paths: set[Path] = field(default_factory=set)
    required_indexes: set[Path] = field(default_factory=set)
    issues: list[ValidationIssue] = field(default_factory=list)


class RepositoryValidator:
    """Validates a single APT repository for presence and hash consistency."""

    MAX_TRANSIENT_RETRIES = 3

    def __init__(
        self,
        repository: BaseRepository,
        config: Config,
        temp_root: Path,
        concurrency: int = 64,
        disable_http2: bool = False,
    ) -> None:
        self._repository = repository
        self._config = config
        self._repo_dir = temp_root / repository.get_mirror_path(config.encode_tilde)
        self._repo_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_hashes = set(config.check_hashes) or set(HashType)
        self._downloader = create_downloader(
            repository,
            config,
            self._repo_dir,
            concurrency,
            disable_http2=disable_http2,
        )

    async def validate(self) -> list[ValidationIssue]:
        state = _RepoMetadataState()
        try:
            for (
                metadata,
                release_paths,
            ) in self._repository.release_files_per_metadata.items():
                await self._process_metadata_release_files(
                    metadata, release_paths, state
                )

            await self._verify_metadata_files(state)
            await self._verify_pool_files(state.issues)
        finally:
            await self._downloader.aclose()
        return state.issues

    async def _fetch_path(
        self,
        source_path: Path,
        hash_types: Iterable[HashType] = HASH_PRIORITY,
        save_to: Path | None = None,
    ) -> FetchResult:
        hash_type_set = set(hash_types)
        tries = self.MAX_TRANSIENT_RETRIES

        while tries > 0:
            tries -= 1
            async with (
                self._downloader._settings.semaphore,  # pylint: disable=W0212
                self._downloader.stream(source_path) as response,
            ):
                if response.missing:
                    return FetchResult(found=False)

                if (response.error or response.retry) and tries > 0:
                    await asyncio.sleep(0.5 * (self.MAX_TRANSIENT_RETRIES - tries))
                    continue

                if response.error or response.retry:
                    return FetchResult(
                        found=False,
                        error=response.error or "connection closed by server",
                    )

                hashers = {ht: ht.get_hash_function()() for ht in hash_type_set}
                size = 0

                if save_to is not None:
                    save_to.parent.mkdir(parents=True, exist_ok=True)

                try:
                    with contextlib.ExitStack() as stack:
                        out_fp = (
                            stack.enter_context(open(save_to, "wb"))
                            if save_to is not None
                            else None
                        )
                        async with contextlib.aclosing(response.stream()) as stream:
                            async for chunk in stream:
                                size += len(chunk)
                                for hasher in hashers.values():
                                    hasher.update(chunk)
                                if out_fp is not None:
                                    out_fp.write(chunk)
                except Exception as ex:  # pylint: disable=W0718
                    if save_to is not None:
                        save_to.unlink(missing_ok=True)
                    if tries > 0:
                        continue
                    return FetchResult(found=False, error=str(ex))

                return FetchResult(
                    found=True,
                    size=size,
                    hashes={ht: h.hexdigest().lower() for ht, h in hashers.items()},
                )

        return FetchResult(found=False)

    async def _download_release_files(
        self,
        metadata: BaseRepositoryMetadata,
        release_paths: Sequence[Path],
        issues: list[ValidationIssue],
    ) -> list[Path]:
        present: list[Path] = []
        for rel_path in release_paths:
            if (
                rel_path.suffix == ".gpg"
                and self._repository.gpg_verify == GPGVerify.OFF
            ):
                continue

            dest = self._repo_dir / rel_path
            result = await self._fetch_path(rel_path, hash_types=(), save_to=dest)
            if result.found and rel_path.suffix != ".gpg":
                present.append(rel_path)

        if not present:
            issues.append(
                ValidationIssue(
                    issue_type=IssueType.MISSING,
                    url=self._repository.url.for_path(metadata.as_path() / "Release"),
                )
            )
            return []

        if self._repository.gpg_verify != GPGVerify.OFF:
            with self._repository._get_merged_gpg_keyring(  # pylint: disable=W0212
                metadata.signed_by,
                self._config.etc_trusted,
                self._config.etc_trusted_parts,
            ) as keyring:
                for rel_path in present:
                    try:
                        self._repository._validate_release_file_signature(  # pylint: disable=W0212
                            self._repo_dir / rel_path, keyring
                        )
                    except InvalidSignatureError as ex:
                        issues.append(
                            ValidationIssue(
                                issue_type=IssueType.HASH_MISMATCH,
                                url=self._repository.url.for_path(rel_path),
                                detail=f"invalid GPG signature: {ex}",
                            )
                        )
        return present

    async def _process_metadata_release_files(
        self,
        metadata: BaseRepositoryMetadata,
        release_paths: Sequence[Path],
        state: _RepoMetadataState,
    ) -> None:
        present_release_files = await self._download_release_files(
            metadata, release_paths, state.issues
        )
        if not present_release_files:
            return

        paths_per_release: dict[Path, set[Path]] = {}
        for rel_path in present_release_files:
            paths_per_release[rel_path] = self._parse_single_release_file(
                metadata, rel_path, state
            )

        if len(paths_per_release) > 1:
            all_paths = set().union(*paths_per_release.values())
            for repo_rel_path in sorted(all_paths):
                present_in = [
                    rel.name
                    for rel, rel_set in paths_per_release.items()
                    if repo_rel_path in rel_set
                ]
                if len(present_in) != len(paths_per_release):
                    state.issues.append(
                        ValidationIssue(
                            issue_type=IssueType.HASH_MISMATCH,
                            url=self._repository.url.for_path(repo_rel_path),
                            detail=(
                                "inconsistent Release/InRelease: only listed in "
                                + ", ".join(present_in)
                            ),
                        )
                    )

        for req_index in self._get_required_index_paths(metadata):
            state.required_indexes.add(req_index)
            if req_index not in state.known_paths:
                state.issues.append(
                    ValidationIssue(
                        issue_type=IssueType.MISSING,
                        url=self._repository.url.for_path(req_index),
                    )
                )

    def _parse_single_release_file(
        self,
        metadata: BaseRepositoryMetadata,
        rel_path: Path,
        state: _RepoMetadataState,
    ) -> set[Path]:
        release_full_path = self._repo_dir / rel_path
        with open(release_full_path, "rt", encoding="utf-8", errors="replace") as fp:
            release = Release(fp)

        seen_in_this_release: set[Path] = set()
        for hash_type in HashType:
            for file_entry in release.get(hash_type.value, []):
                raw_name = file_entry.get("name", "")
                if not raw_name or raw_name in self._repository.RELEASE_FILES:
                    continue

                entry_path = Path(raw_name)
                repo_rel_path = rel_path.parent / entry_path
                if not is_safe_path(self._repo_dir, entry_path):
                    state.issues.append(
                        ValidationIssue(
                            issue_type=IssueType.HASH_MISMATCH,
                            url=self._repository.url.for_path(repo_rel_path),
                            detail="unsafe path in Release file",
                        )
                    )
                    continue

                if not self._repository._metadata_file_allowed(  # pylint: disable=W0212
                    metadata, entry_path
                ):
                    continue

                try:
                    size = int(file_entry["size"])
                except (KeyError, ValueError):
                    size = -1

                uncompressed_path = DownloadFile.uncompressed_path(repo_rel_path)
                state.known_paths.add(uncompressed_path)

                if size < 0:
                    state.issues.append(
                        ValidationIssue(
                            issue_type=IssueType.HASH_MISMATCH,
                            url=self._repository.url.for_path(repo_rel_path),
                            detail="invalid size in Release file",
                        )
                    )
                    continue

                if size > 0:
                    seen_in_this_release.add(repo_rel_path)

                compression = _detect_compression(repo_rel_path)
                variant_map = state.groups.setdefault(uncompressed_path, {})
                expected_file = variant_map.setdefault(
                    compression,
                    ExpectedFile(
                        path=repo_rel_path,
                        ignore_errors=should_ignore_errors(
                            self._repository.ignore_errors, uncompressed_path
                        ),
                    ),
                )
                expected_file.add_expectation(
                    size=size,
                    hashes={hash_type: file_entry[hash_type.value]},
                )

        return seen_in_this_release

    def _get_required_index_paths(self, metadata: BaseRepositoryMetadata) -> list[Path]:
        required: list[Path] = []
        if isinstance(self._repository, Repository):
            codename = self._repository.codenames.get_codename(metadata.as_string())
            for component in codename.components.values():
                if component.mirror_source:
                    required.append(
                        Repository.DISTS
                        / codename.as_string()
                        / component.name
                        / "source"
                        / "Sources"
                    )
                for arch in component.arches:
                    required.append(
                        Repository.DISTS
                        / codename.as_string()
                        / component.name
                        / f"binary-{arch}"
                        / "Packages"
                    )
        elif isinstance(self._repository, FlatRepository):
            directory = self._repository.directories.get_directory(metadata.as_path())
            if directory.mirror_source:
                required.append(directory.as_path() / "Sources")
            if directory.mirror_binaries:
                required.append(directory.as_path() / "Packages")

        return required

    async def _verify_metadata_files(self, state: _RepoMetadataState) -> None:
        tasks = [
            self._verify_single_metadata_group(
                uncompressed_path,
                variants_map,
                is_required_index=uncompressed_path in state.required_indexes,
            )
            for uncompressed_path, variants_map in sorted(
                state.groups.items(), key=lambda item: str(item[0])
            )
        ]
        results = await asyncio.gather(*tasks)
        for group_issues in results:
            state.issues.extend(group_issues)

    async def _verify_single_metadata_group(
        self,
        uncompressed_path: Path,
        variants_map: Mapping[FileCompression, ExpectedFile],
        is_required_index: bool,
    ) -> list[ValidationIssue]:
        group_issues: list[ValidationIssue] = []

        for comp in FileCompression:
            if comp in variants_map and not variants_map[comp].ignore_errors:
                conflict = self._check_internal_expectation_conflict(variants_map[comp])
                if conflict is not None:
                    group_issues.append(conflict)

        compressed_variants = {
            comp: ef
            for comp, ef in variants_map.items()
            if comp != FileCompression.NONE and ef.sizes != {0}
        }
        uncompressed_ef = variants_map.get(FileCompression.NONE)

        valid_compressed: list[tuple[FileCompression, Path, ExpectedFile]] = []
        downloaded_compressed: list[tuple[FileCompression, Path, ExpectedFile]] = []
        missing_compressed: list[ExpectedFile] = []

        for comp in (FileCompression.XZ, FileCompression.GZ, FileCompression.BZ2):
            if comp not in compressed_variants:
                continue

            ef = compressed_variants[comp]
            dest = self._repo_dir / ef.path
            url = self._repository.url.for_path(ef.path)
            result = await self._fetch_path(
                ef.path,
                hash_types=ef.hashes.keys() or HASH_PRIORITY,
                save_to=dest,
            )

            if not result.found:
                missing_compressed.append(ef)
                continue

            downloaded_compressed.append((comp, dest, ef))
            mismatch = ef.verify(url, result.size, result.hashes, self._enabled_hashes)
            if mismatch is not None:
                self._append_unique_issue(group_issues, mismatch, ef.ignore_errors)
            else:
                valid_compressed.append((comp, dest, ef))

        uncompressed_dest = self._repo_dir / uncompressed_path
        uncompressed_on_server = await self._check_uncompressed_on_server(
            uncompressed_ef, uncompressed_dest, group_issues
        )

        self._report_missing_metadata_variants(
            compressed_variants=compressed_variants,
            uncompressed_ef=uncompressed_ef,
            downloaded_compressed=downloaded_compressed,
            missing_compressed=missing_compressed,
            uncompressed_on_server=uncompressed_on_server,
            is_required_index=is_required_index,
            group_issues=group_issues,
        )

        await self._verify_decompressed_variants(
            uncompressed_path=uncompressed_path,
            uncompressed_dest=uncompressed_dest,
            uncompressed_ef=uncompressed_ef,
            uncompressed_on_server=uncompressed_on_server,
            valid_compressed=valid_compressed,
            downloaded_compressed=downloaded_compressed,
            group_issues=group_issues,
        )

        return group_issues

    async def _check_uncompressed_on_server(
        self,
        uncompressed_ef: ExpectedFile | None,
        uncompressed_dest: Path,
        group_issues: list[ValidationIssue],
    ) -> bool:
        if uncompressed_ef is None:
            return False

        url = self._repository.url.for_path(uncompressed_ef.path)
        result = await self._fetch_path(
            uncompressed_ef.path,
            hash_types=uncompressed_ef.hashes.keys() or HASH_PRIORITY,
            save_to=uncompressed_dest,
        )
        if not result.found:
            return False

        mismatch = uncompressed_ef.verify(
            url, result.size, result.hashes, self._enabled_hashes
        )
        if mismatch is not None:
            self._append_unique_issue(
                group_issues, mismatch, uncompressed_ef.ignore_errors
            )
        return True

    def _report_missing_metadata_variants(
        self,
        *,
        compressed_variants: Mapping[FileCompression, ExpectedFile],
        uncompressed_ef: ExpectedFile | None,
        downloaded_compressed: Sequence[tuple[FileCompression, Path, ExpectedFile]],
        missing_compressed: Sequence[ExpectedFile],
        uncompressed_on_server: bool,
        is_required_index: bool,
        group_issues: list[ValidationIssue],
    ) -> None:
        is_empty_index = (
            not compressed_variants
            and uncompressed_ef is not None
            and uncompressed_ef.sizes == {0}
        )
        if downloaded_compressed and not uncompressed_on_server:
            for ef in missing_compressed:
                self._append_unique_issue(
                    group_issues,
                    ValidationIssue(
                        issue_type=IssueType.MISSING,
                        url=self._repository.url.for_path(ef.path),
                    ),
                    ef.ignore_errors,
                )
        elif (
            not downloaded_compressed
            and not uncompressed_on_server
            and is_required_index
            and not is_empty_index
        ):
            if missing_compressed:
                for ef in missing_compressed:
                    self._append_unique_issue(
                        group_issues,
                        ValidationIssue(
                            issue_type=IssueType.MISSING,
                            url=self._repository.url.for_path(ef.path),
                        ),
                        ef.ignore_errors,
                    )
            elif uncompressed_ef is not None:
                self._append_unique_issue(
                    group_issues,
                    ValidationIssue(
                        issue_type=IssueType.MISSING,
                        url=self._repository.url.for_path(uncompressed_ef.path),
                    ),
                    uncompressed_ef.ignore_errors,
                )

    async def _verify_decompressed_variants(
        self,
        *,
        uncompressed_path: Path,
        uncompressed_dest: Path,
        uncompressed_ef: ExpectedFile | None,
        uncompressed_on_server: bool,
        valid_compressed: Sequence[tuple[FileCompression, Path, ExpectedFile]],
        downloaded_compressed: Sequence[tuple[FileCompression, Path, ExpectedFile]],
        group_issues: list[ValidationIssue],
    ) -> None:
        candidates = valid_compressed or downloaded_compressed
        decompressed_digests: dict[str, Path] = {}
        uncompressed_verified = False

        for comp, comp_path, comp_ef in candidates:
            target_file = (
                uncompressed_dest
                if not uncompressed_dest.exists() or not uncompressed_on_server
                else None
            )
            needed_hashes = (
                set(uncompressed_ef.hashes.keys()) | {HashType.SHA256}
                if uncompressed_ef is not None
                else {HashType.SHA256}
            )
            try:
                dec_size, dec_hashes = await asyncio.to_thread(
                    _decompress_and_hash,
                    comp_path,
                    comp,
                    target_file,
                    needed_hashes,
                )
            except (lzma.LZMAError, OSError, EOFError, ValueError) as ex:
                if (comp, comp_path, comp_ef) in valid_compressed:
                    self._append_unique_issue(
                        group_issues,
                        ValidationIssue(
                            issue_type=IssueType.HASH_MISMATCH,
                            url=self._repository.url.for_path(comp_ef.path),
                            detail=f"corrupt compressed archive: {ex}",
                        ),
                        comp_ef.ignore_errors,
                    )
                continue

            if (comp, comp_path, comp_ef) in valid_compressed:
                sha256_digest = dec_hashes.get(HashType.SHA256, "")
                decompressed_digests.setdefault(sha256_digest, comp_ef.path)

                if (
                    uncompressed_ef is not None
                    and not uncompressed_on_server
                    and not uncompressed_verified
                ):
                    uncompressed_verified = True
                    mismatch = uncompressed_ef.verify(
                        self._repository.url.for_path(uncompressed_ef.path),
                        dec_size,
                        dec_hashes,
                        self._enabled_hashes,
                    )
                    if mismatch is not None:
                        self._append_unique_issue(
                            group_issues, mismatch, uncompressed_ef.ignore_errors
                        )

        if len(decompressed_digests) > 1:
            self._append_unique_issue(
                group_issues,
                ValidationIssue(
                    issue_type=IssueType.HASH_MISMATCH,
                    url=self._repository.url.for_path(uncompressed_path),
                    detail="compressed variants decompress to different contents",
                ),
                False,
            )

    @staticmethod
    def _append_unique_issue(
        issues: list[ValidationIssue],
        issue: ValidationIssue,
        ignore_errors: bool,
    ) -> None:
        if not ignore_errors and all(existing.url != issue.url for existing in issues):
            issues.append(issue)

    def _check_internal_expectation_conflict(
        self, expected_file: ExpectedFile
    ) -> ValidationIssue | None:
        url = self._repository.url.for_path(expected_file.path)
        for hash_type in HASH_PRIORITY:
            digests = sorted(expected_file.hashes.get(hash_type, ()))
            if len(digests) > 1:
                return ValidationIssue(
                    issue_type=IssueType.HASH_MISMATCH,
                    url=url,
                    detail=(
                        f"{hash_type.value}: conflicting expected hashes "
                        f"{digests[0]} != {digests[1]}"
                    ),
                )
        sizes = sorted(expected_file.sizes)
        if len(sizes) > 1:
            return ValidationIssue(
                issue_type=IssueType.HASH_MISMATCH,
                url=url,
                detail=f"size: conflicting expected sizes {sizes[0]} != {sizes[1]}",
            )
        return None

    def _collect_pool_files(self) -> dict[Path, ExpectedFile]:
        expected_pool_files: dict[Path, ExpectedFile] = {}

        if self._repository.is_source_enabled:
            if isinstance(self._repository, FlatRepository):
                source_indexes = {
                    d.as_path() / "Sources"
                    for d in self._repository.directories.values()
                    if d.mirror_source
                }
            else:
                source_indexes = set(self._repository.sources_files)

            existing_source_indexes = {
                idx for idx in source_indexes if self._index_exists(idx)
            }
            sources_parser = SourcesParser(
                repository_path=self._repo_dir,
                index_files=existing_source_indexes,
                ignore_errors=self._repository.ignore_errors,
                weak_size_check=False,
                package_filter=self._repository.package_filter,
                logger_id=self._repository.url,
            )
            sources_parser._pool_files = _PoolCollectorDict(expected_pool_files)  # pylint: disable=W0212
            sources_parser.parse()

        if self._repository.is_binaries_enabled:
            if isinstance(self._repository, FlatRepository):
                package_indexes = {
                    d.as_path() / "Packages"
                    for d in self._repository.directories.values()
                    if d.mirror_binaries
                }
            else:
                package_indexes = set(self._repository.packages_files)

            existing_package_indexes = {
                idx for idx in package_indexes if self._index_exists(idx)
            }
            packages_parser = PackagesParser(
                repository_path=self._repo_dir,
                index_files=existing_package_indexes,
                ignore_errors=self._repository.ignore_errors,
                weak_size_check=False,
                package_filter=self._repository.package_filter,
                logger_id=self._repository.url,
            )
            packages_parser._pool_files = _PoolCollectorDict(expected_pool_files)  # pylint: disable=W0212
            packages_parser.parse()

        return expected_pool_files

    def _index_exists(self, relative_index_path: Path) -> bool:
        base = self._repo_dir / relative_index_path
        if base.is_file():
            return True
        return any(
            base.with_name(f"{base.name}{suffix}").is_file()
            for suffix in BaseRepository.COMPRESSION_SUFFIXES
        )

    async def _verify_pool_files(self, issues: list[ValidationIssue]) -> None:
        expected_pool_files = await asyncio.to_thread(self._collect_pool_files)

        sorted_pool_files = [
            ef
            for _, ef in sorted(
                expected_pool_files.items(), key=lambda item: str(item[0])
            )
            if not ef.ignore_errors
        ]

        if not sorted_pool_files:
            return

        total_files = len(sorted_pool_files)
        queue: asyncio.Queue[ExpectedFile | None] = asyncio.Queue()
        for ef in sorted_pool_files:
            queue.put_nowait(ef)

        num_workers = min(
            len(sorted_pool_files),
            max(1, getattr(self._downloader._settings.semaphore, "_value", 64)),
        )
        for _ in range(num_workers):
            queue.put_nowait(None)

        completed = 0
        pool_issues: list[ValidationIssue] = []
        lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal completed
            while True:
                item = await queue.get()
                if item is None:
                    queue.task_done()
                    break
                try:
                    issue = await self._verify_single_pool_file(item)
                    if issue is not None:
                        async with lock:
                            pool_issues.append(issue)
                finally:
                    queue.task_done()
                    async with lock:
                        completed += 1
                        if completed % 1000 == 0 or completed == total_files:
                            logging.info(
                                "Verified pool files for %s: %d/%d (%d issues)",
                                self._repository.url,
                                completed,
                                total_files,
                                len(pool_issues),
                            )

        workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
        await asyncio.gather(*workers)
        issues.extend(pool_issues)

    async def _verify_single_pool_file(
        self, expected_file: ExpectedFile
    ) -> ValidationIssue | None:
        url = self._repository.url.for_path(expected_file.path)
        conflict = self._check_internal_expectation_conflict(expected_file)
        if conflict is not None:
            return conflict

        result = await self._fetch_path(
            expected_file.path,
            hash_types=expected_file.hashes.keys() or HASH_PRIORITY,
            save_to=None,
        )
        if not result.found:
            return ValidationIssue(
                issue_type=IssueType.MISSING,
                url=url,
                detail=result.error,
            )

        return expected_file.verify(
            url, result.size, result.hashes, self._enabled_hashes
        )


def _is_deb822_file(path: Path) -> bool:
    if path.suffix == ".sources":
        return True
    try:
        with open(path, "rt", encoding="utf-8") as fp:
            for line in fp:
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", ";")):
                    continue
                return stripped.startswith(("Types:", "URIs:", "Enabled:"))
    except OSError:
        return False
    return False


def _sanitize_list_line(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return stripped
    if stripped.startswith("deb"):
        for idx, ch in enumerate(stripped):
            if ch == "#" and (idx == 0 or stripped[idx - 1].isspace()):
                return stripped[:idx].rstrip()
    return stripped


def _read_sanitized_lines(path: Path) -> list[str]:
    lines: list[str] = []
    with open(path, "rt", encoding="utf-8") as fp:
        for raw_line in fp:
            cleaned = _sanitize_list_line(raw_line)
            if cleaned:
                lines.append(cleaned)
    return lines


def load_config(config_files: Sequence[Path], temp_dir: Path) -> Config:
    combined_list = temp_dir / "mirror.list"
    combined_d = temp_dir / "mirror.list.d"
    combined_d.mkdir(parents=True, exist_ok=True)

    list_lines: list[str] = []
    deb822_counter = 0

    for cfg_path in config_files:
        if not cfg_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {cfg_path}")

        if _is_deb822_file(cfg_path):
            deb822_counter += 1
            shutil.copyfile(
                cfg_path, combined_d / f"{deb822_counter:04d}_{cfg_path.name}.sources"
            )
        else:
            list_lines.extend(_read_sanitized_lines(cfg_path))

        cfg_d = cfg_path.with_name(f"{cfg_path.name}.d")
        if cfg_d.is_dir():
            for child in sorted(cfg_d.iterdir()):
                if not child.is_file():
                    continue
                if child.suffix == ".sources":
                    deb822_counter += 1
                    shutil.copyfile(
                        child,
                        combined_d / f"{deb822_counter:04d}_{child.name}",
                    )
                elif child.suffix == ".list":
                    list_lines.extend(_read_sanitized_lines(child))

    with open(combined_list, "wt", encoding="utf-8") as fp:
        fp.write("\n".join(list_lines) + "\n")

    return Config(combined_list, default_base_path=str(temp_dir))


async def validate_config_files(
    config_files: Sequence[Path],
    concurrency: int = 64,
    disable_http2: bool = False,
    on_issue: Callable[[ValidationIssue], None] | None = None,
) -> list[ValidationIssue]:
    with TemporaryDirectory(prefix="apt-mirror2-validate.") as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        config = load_config(config_files, tmp_dir / "cfg")

        if not config.repositories:
            raise ValueError("No repositories found in configuration")

        all_issues: list[ValidationIssue] = []
        repo_work_root = tmp_dir / "work"

        for repository in config.repositories.values():
            validator = RepositoryValidator(
                repository=repository,
                config=config,
                temp_root=repo_work_root,
                concurrency=concurrency,
                disable_http2=disable_http2,
            )
            repo_issues = await validator.validate()
            for issue in repo_issues:
                if on_issue is not None:
                    on_issue(issue)
            all_issues.extend(repo_issues)

        return all_issues


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate that APT repositories in a sources.list / mirror.list "
            "are valid and self-consistent."
        )
    )
    parser.add_argument(
        "config_files",
        nargs="+",
        type=Path,
        help="Path(s) to APT sources.list, .sources, or mirror.list file(s)",
    )
    parser.add_argument(
        "-j",
        "--concurrency",
        type=int,
        default=64,
        help="Maximum concurrent requests per repository (default: 64)",
    )
    parser.add_argument(
        "--disable-http2",
        action="store_true",
        help="Disable HTTP/2 to improve streaming throughput with HTTP/1.1",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    log_level = logging.INFO if args.verbose else logging.ERROR
    LoggerFactory.DEFAULT_LOGLEVEL = log_level
    logging.getLogger().setLevel(log_level)

    try:
        issues = asyncio.run(
            validate_config_files(
                config_files=args.config_files,
                concurrency=max(1, args.concurrency),
                disable_http2=args.disable_http2,
                on_issue=lambda issue: print(issue.format_line(), flush=True),
            )
        )
    except (FileNotFoundError, ValueError) as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return 2

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
