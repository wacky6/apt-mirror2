# SPDX-License-Identifier: GPL-3.0-or-later

import bz2
import contextlib
import gzip
import hashlib
import io
import lzma
import shutil
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import IsolatedAsyncioTestCase

from validate_repo import IssueType, main, validate_config_files


class _QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # pylint: disable=W0622
        pass


def _all_hashes(data: bytes) -> dict[str, str]:
    return {
        "MD5Sum": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "SHA512": hashlib.sha512(data).hexdigest(),
    }


def _build_release_content(
    codename: str,
    components: list[str],
    arches: list[str],
    entries: dict[str, tuple[int, dict[str, str]]],
    inrelease: bool = False,
) -> str:
    lines = [
        "Origin: LocalTest",
        "Label: LocalTest",
        f"Suite: {codename}",
        f"Codename: {codename}",
        f"Components: {' '.join(components)}",
        f"Architectures: {' '.join(arches)}",
    ]

    for hash_key in ("MD5Sum", "SHA1", "SHA256", "SHA512"):
        lines.append(f"{hash_key}:")
        for rel_name, (size, digests) in sorted(entries.items()):
            if hash_key in digests:
                lines.append(f" {digests[hash_key]} {size} {rel_name}")

    body = "\n".join(lines) + "\n"
    if not inrelease:
        return body

    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n\n"
        f"{body}"
        "-----BEGIN PGP SIGNATURE-----\n\n"
        "iQIzBAEBCAAdFiEE000000000000000000000000000FAl00000ACgkQ00000000\n"
        "=0000\n"
        "-----END PGP SIGNATURE-----\n"
    )


class TestValidateRepo(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._tmp_dir_obj = TemporaryDirectory(prefix="apt-mirror2-test-validate.")
        self.tmp_dir = Path(self._tmp_dir_obj.name)
        self.repo_root = self.tmp_dir / "repo"
        self.repo_root.mkdir(parents=True, exist_ok=True)

        handler = partial(_QuietHTTPRequestHandler, directory=str(self.repo_root))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_port
        self.base_url = f"http://127.0.0.1:{self.port}"

        self._server_thread = threading.Thread(
            target=self.httpd.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self._server_thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._server_thread.join(timeout=5)
        self._tmp_dir_obj.cleanup()
        super().tearDown()

    def _create_standard_repo(
        self,
        keep_uncompressed_indexes: bool = False,
        include_sources: bool = True,
    ) -> dict[str, Path]:
        dists_dir = self.repo_root / "dists" / "bookworm"
        bin_dir = dists_dir / "main" / "binary-amd64"
        src_dir = dists_dir / "main" / "source"
        pool_dir = self.repo_root / "pool" / "main" / "h" / "hello"

        bin_dir.mkdir(parents=True, exist_ok=True)
        src_dir.mkdir(parents=True, exist_ok=True)
        pool_dir.mkdir(parents=True, exist_ok=True)

        deb1_rel = Path("pool/main/h/hello/hello_1.0-1_amd64.deb")
        deb2_rel = Path("pool/main/h/hello/hello-doc_1.0-1_all.deb")
        dsc_rel = Path("pool/main/h/hello/hello_1.0-1.dsc")
        tar_rel = Path("pool/main/h/hello/hello_1.0.orig.tar.gz")

        deb1_bytes = b"DUMMY_DEB_1_CONTENT" * 50
        deb2_bytes = b"DUMMY_DEB_2_CONTENT" * 40
        dsc_bytes = b"Format: 3.0 (quilt)\nSource: hello\nVersion: 1.0-1\n"
        tar_bytes = b"DUMMY_ORIG_TAR_GZ_CONTENT" * 30

        (self.repo_root / deb1_rel).write_bytes(deb1_bytes)
        (self.repo_root / deb2_rel).write_bytes(deb2_bytes)
        (self.repo_root / dsc_rel).write_bytes(dsc_bytes)
        (self.repo_root / tar_rel).write_bytes(tar_bytes)

        deb1_hashes = _all_hashes(deb1_bytes)
        deb2_hashes = _all_hashes(deb2_bytes)
        dsc_hashes = _all_hashes(dsc_bytes)
        tar_hashes = _all_hashes(tar_bytes)

        packages_text = (
            "Package: hello\n"
            "Version: 1.0-1\n"
            "Architecture: amd64\n"
            "Section: main\n"
            f"Filename: {deb1_rel}\n"
            f"Size: {len(deb1_bytes)}\n"
            f"MD5sum: {deb1_hashes['MD5Sum']}\n"
            f"SHA1: {deb1_hashes['SHA1']}\n"
            f"SHA256: {deb1_hashes['SHA256']}\n"
            f"SHA512: {deb1_hashes['SHA512']}\n"
            "\n"
            "Package: hello-doc\n"
            "Source: hello\n"
            "Version: 1.0-1\n"
            "Architecture: all\n"
            "Section: doc\n"
            f"Filename: {deb2_rel}\n"
            f"Size: {len(deb2_bytes)}\n"
            f"MD5sum: {deb2_hashes['MD5Sum']}\n"
            f"SHA1: {deb2_hashes['SHA1']}\n"
            f"SHA256: {deb2_hashes['SHA256']}\n"
            f"SHA512: {deb2_hashes['SHA512']}\n"
            "\n"
        )
        packages_bytes = packages_text.encode("utf-8")
        packages_gz = gzip.compress(packages_bytes)
        packages_xz = lzma.compress(packages_bytes)

        if keep_uncompressed_indexes:
            (bin_dir / "Packages").write_bytes(packages_bytes)
        (bin_dir / "Packages.gz").write_bytes(packages_gz)
        (bin_dir / "Packages.xz").write_bytes(packages_xz)

        release_entries: dict[str, tuple[int, dict[str, str]]] = {
            "main/binary-amd64/Packages": (
                len(packages_bytes),
                _all_hashes(packages_bytes),
            ),
            "main/binary-amd64/Packages.gz": (
                len(packages_gz),
                _all_hashes(packages_gz),
            ),
            "main/binary-amd64/Packages.xz": (
                len(packages_xz),
                _all_hashes(packages_xz),
            ),
        }

        if include_sources:
            sources_text = (
                "Package: hello\n"
                "Version: 1.0-1\n"
                "Section: main\n"
                "Directory: pool/main/h/hello\n"
                "Files:\n"
                f" {dsc_hashes['MD5Sum']} {len(dsc_bytes)} {dsc_rel.name}\n"
                f" {tar_hashes['MD5Sum']} {len(tar_bytes)} {tar_rel.name}\n"
                "Checksums-Sha1:\n"
                f" {dsc_hashes['SHA1']} {len(dsc_bytes)} {dsc_rel.name}\n"
                f" {tar_hashes['SHA1']} {len(tar_bytes)} {tar_rel.name}\n"
                "Checksums-Sha256:\n"
                f" {dsc_hashes['SHA256']} {len(dsc_bytes)} {dsc_rel.name}\n"
                f" {tar_hashes['SHA256']} {len(tar_bytes)} {tar_rel.name}\n"
                "Checksums-Sha512:\n"
                f" {dsc_hashes['SHA512']} {len(dsc_bytes)} {dsc_rel.name}\n"
                f" {tar_hashes['SHA512']} {len(tar_bytes)} {tar_rel.name}\n"
                "\n"
            )
            sources_bytes = sources_text.encode("utf-8")
            sources_gz = gzip.compress(sources_bytes)
            sources_bz2 = bz2.compress(sources_bytes)

            if keep_uncompressed_indexes:
                (src_dir / "Sources").write_bytes(sources_bytes)
            (src_dir / "Sources.gz").write_bytes(sources_gz)
            (src_dir / "Sources.bz2").write_bytes(sources_bz2)

            release_entries["main/source/Sources"] = (
                len(sources_bytes),
                _all_hashes(sources_bytes),
            )
            release_entries["main/source/Sources.gz"] = (
                len(sources_gz),
                _all_hashes(sources_gz),
            )
            release_entries["main/source/Sources.bz2"] = (
                len(sources_bz2),
                _all_hashes(sources_bz2),
            )

        (dists_dir / "Release").write_text(
            _build_release_content(
                "bookworm",
                ["main"],
                ["amd64"],
                release_entries,
                inrelease=False,
            ),
            encoding="utf-8",
        )
        (dists_dir / "InRelease").write_text(
            _build_release_content(
                "bookworm",
                ["main"],
                ["amd64"],
                release_entries,
                inrelease=True,
            ),
            encoding="utf-8",
        )

        return {
            "deb1": self.repo_root / deb1_rel,
            "deb2": self.repo_root / deb2_rel,
            "dsc": self.repo_root / dsc_rel,
            "tar": self.repo_root / tar_rel,
            "packages_gz": bin_dir / "Packages.gz",
            "packages_xz": bin_dir / "Packages.xz",
            "sources_gz": src_dir / "Sources.gz",
            "release": dists_dir / "Release",
            "inrelease": dists_dir / "InRelease",
        }

    def _write_sources_list(self, content: str, name: str = "sources.list") -> Path:
        cfg_path = self.tmp_dir / name
        cfg_path.write_text(content, encoding="utf-8")
        return cfg_path

    def _run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout_buf),
            contextlib.redirect_stderr(stderr_buf),
        ):
            rc = main(list(args))
        return rc, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_valid_repository_passes(self) -> None:
        self._create_standard_repo(keep_uncompressed_indexes=False)
        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main # inline comment\n"
            f"deb-src {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "")

    def test_corrupted_and_missing_deb_packages(self) -> None:
        paths = self._create_standard_repo()
        # Corrupt deb1 and delete deb2
        paths["deb1"].write_bytes(b"CORRUPTED_PACKAGE_DATA")
        paths["deb2"].unlink()

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(len(lines), 2, f"Expected 2 lines, got: {lines}")

        deb1_url = f"{self.base_url}/pool/main/h/hello/hello_1.0-1_amd64.deb"
        deb2_url = f"{self.base_url}/pool/main/h/hello/hello-doc_1.0-1_all.deb"

        self.assertTrue(
            any(line.startswith(f"HASH_MISMATCH {deb1_url} (") for line in lines),
            f"Missing HASH_MISMATCH for deb1 in {lines}",
        )
        self.assertIn(f"MISSING {deb2_url}", lines)

    def test_corrupted_and_missing_source_packages(self) -> None:
        paths = self._create_standard_repo()
        paths["dsc"].write_bytes(b"TAMPERED_DSC")
        paths["tar"].unlink()

        sources_list = self._write_sources_list(
            f"deb-src {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(len(lines), 2, f"Expected 2 lines, got: {lines}")

        dsc_url = f"{self.base_url}/pool/main/h/hello/hello_1.0-1.dsc"
        tar_url = f"{self.base_url}/pool/main/h/hello/hello_1.0.orig.tar.gz"

        self.assertTrue(
            any(line.startswith(f"HASH_MISMATCH {dsc_url} (") for line in lines),
            f"Missing HASH_MISMATCH for dsc in {lines}",
        )
        self.assertIn(f"MISSING {tar_url}", lines)

    def test_corrupted_package_index_detected(self) -> None:
        paths = self._create_standard_repo()
        # Corrupt Packages.gz on server while Packages.xz remains valid
        paths["packages_gz"].write_bytes(gzip.compress(b"corrupted-index"))

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(len(lines), 1, f"Expected 1 line, got: {lines}")
        pkg_gz_url = f"{self.base_url}/dists/bookworm/main/binary-amd64/Packages.gz"
        self.assertTrue(lines[0].startswith(f"HASH_MISMATCH {pkg_gz_url} ("))

    def test_missing_compressed_index_variant_detected(self) -> None:
        paths = self._create_standard_repo(keep_uncompressed_indexes=False)
        # Delete Packages.xz while Release still advertises it
        paths["packages_xz"].unlink()

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        pkg_xz_url = f"{self.base_url}/dists/bookworm/main/binary-amd64/Packages.xz"
        self.assertEqual(lines, [f"MISSING {pkg_xz_url}"])

    def test_decompressed_index_mismatch_against_uncompressed_release_entry(
        self,
    ) -> None:
        paths = self._create_standard_repo(keep_uncompressed_indexes=False)
        # Replace uncompressed Packages hash in Release/InRelease with wrong hash
        wrong_hash = "f" * 64
        for rel_file in (paths["release"], paths["inrelease"]):
            text = rel_file.read_text(encoding="utf-8")
            for line in text.splitlines():
                if (
                    line.endswith(" main/binary-amd64/Packages")
                    and len(line.strip().split()[0]) == 64
                ):
                    old_hash = line.strip().split()[0]
                    text = text.replace(old_hash, wrong_hash)
            rel_file.write_text(text, encoding="utf-8")

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        pkg_url = f"{self.base_url}/dists/bookworm/main/binary-amd64/Packages"
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(f"HASH_MISMATCH {pkg_url} (SHA256:"))

    def test_unsynced_release_and_inrelease_detected(self) -> None:
        paths = self._create_standard_repo()
        # Tamper with a hash in InRelease so it disagrees with Release
        inrelease_text = paths["inrelease"].read_text(encoding="utf-8")
        for line in inrelease_text.splitlines():
            if (
                line.endswith(" main/binary-amd64/Packages.gz")
                and len(line.strip().split()[0]) == 64
            ):
                old_hash = line.strip().split()[0]
                inrelease_text = inrelease_text.replace(old_hash, "0" * 64)
                break
        paths["inrelease"].write_text(inrelease_text, encoding="utf-8")

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        pkg_gz_url = f"{self.base_url}/dists/bookworm/main/binary-amd64/Packages.gz"
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(f"HASH_MISMATCH {pkg_gz_url} ("))

    def test_missing_release_files_detected(self) -> None:
        paths = self._create_standard_repo()
        paths["release"].unlink()
        paths["inrelease"].unlink()

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(lines, [f"MISSING {self.base_url}/dists/bookworm/Release"])

    def test_missing_component_index_in_release_detected(self) -> None:
        self._create_standard_repo()
        # Request component 'contrib' which is not in Release
        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main contrib\n"
        )

        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)

        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(
            lines,
            [f"MISSING {self.base_url}/dists/bookworm/contrib/binary-amd64/Packages"],
        )

    def test_flat_repository_and_deb822_sources_and_file_url(self) -> None:
        flat_dir = self.repo_root / "flat"
        flat_dir.mkdir(parents=True, exist_ok=True)

        deb_rel = Path("flat/hello_1.0_amd64.deb")
        deb_bytes = b"FLAT_DEB_BINARY_DATA"
        (self.repo_root / deb_rel).write_bytes(deb_bytes)
        deb_hashes = _all_hashes(deb_bytes)

        packages_bytes = (
            "Package: hello\n"
            "Version: 1.0\n"
            "Architecture: amd64\n"
            f"Filename: {deb_rel}\n"
            f"Size: {len(deb_bytes)}\n"
            f"SHA256: {deb_hashes['SHA256']}\n\n"
        ).encode()
        (flat_dir / "Packages").write_bytes(packages_bytes)
        pkg_hashes = _all_hashes(packages_bytes)

        release_text = (
            "Origin: FlatRepo\n"
            "SHA256:\n"
            f" {pkg_hashes['SHA256']} {len(packages_bytes)} Packages\n"
        )
        (flat_dir / "Release").write_text(release_text, encoding="utf-8")

        # 1. Valid Deb822 .sources over HTTP
        deb822_file = self._write_sources_list(
            f"Types: deb\n"
            f"URIs: {self.base_url}\n"
            f"Suites: flat/\n"
            f"Architectures: amd64\n",
            name="repo.sources",
        )
        rc, stdout, _ = self._run_cli(str(deb822_file))
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "")

        # 2. Valid file:// URL
        file_list = self._write_sources_list(
            f"deb [arch=amd64] file://{self.repo_root} flat/\n",
            name="file.list",
        )
        rc, stdout, _ = self._run_cli(str(file_list))
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "")

        # 3. Corrupt flat package and verify HASH_MISMATCH
        (self.repo_root / deb_rel).write_bytes(b"CORRUPT")
        rc, stdout, _ = self._run_cli(str(deb822_file))
        self.assertEqual(rc, 1)
        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertEqual(len(lines), 1)
        self.assertTrue(
            lines[0].startswith(f"HASH_MISMATCH {self.base_url}/{deb_rel} (")
        )

    async def test_conflicting_stanzas_for_same_package_path(self) -> None:
        self._create_standard_repo(
            keep_uncompressed_indexes=True, include_sources=False
        )
        bin_dir = self.repo_root / "dists" / "bookworm" / "main" / "binary-amd64"
        packages_file = bin_dir / "Packages"

        # Append a conflicting stanza for the same Filename with a different SHA256
        orig_text = packages_file.read_text(encoding="utf-8")
        conflicting_stanza = (
            "Package: hello-duplicate\n"
            "Version: 1.0-1\n"
            "Architecture: amd64\n"
            "Filename: pool/main/h/hello/hello_1.0-1_amd64.deb\n"
            "Size: 950\n"
            f"SHA256: {'a' * 64}\n\n"
        )
        new_bytes = (orig_text + conflicting_stanza).encode("utf-8")
        packages_file.write_bytes(new_bytes)
        (bin_dir / "Packages.gz").write_bytes(gzip.compress(new_bytes))
        (bin_dir / "Packages.xz").write_bytes(lzma.compress(new_bytes))

        release_entries = {
            "main/binary-amd64/Packages": (len(new_bytes), _all_hashes(new_bytes)),
            "main/binary-amd64/Packages.gz": (
                (bin_dir / "Packages.gz").stat().st_size,
                _all_hashes((bin_dir / "Packages.gz").read_bytes()),
            ),
            "main/binary-amd64/Packages.xz": (
                (bin_dir / "Packages.xz").stat().st_size,
                _all_hashes((bin_dir / "Packages.xz").read_bytes()),
            ),
        }
        dists_dir = self.repo_root / "dists" / "bookworm"
        (dists_dir / "Release").write_text(
            _build_release_content("bookworm", ["main"], ["amd64"], release_entries),
            encoding="utf-8",
        )
        (dists_dir / "InRelease").unlink(missing_ok=True)

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bookworm main\n"
        )
        issues = await validate_config_files([sources_list])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].issue_type, IssueType.HASH_MISMATCH)
        self.assertEqual(
            issues[0].url,
            f"{self.base_url}/pool/main/h/hello/hello_1.0-1_amd64.deb",
        )

    def test_existing_ignore_errors_test_data_repo(self) -> None:
        # Copy tests/data/IgnoreErrorsConfig/repository into self.repo_root
        src_repo = Path(__file__).parent / "data" / "IgnoreErrorsConfig" / "repository"
        shutil.rmtree(self.repo_root)
        shutil.copytree(src_repo, self.repo_root)

        sources_list = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bullseye main\n"
        )
        rc, stdout, _ = self._run_cli(str(sources_list))
        self.assertEqual(rc, 1)
        lines = [line for line in stdout.strip().splitlines() if line]
        self.assertTrue(len(lines) > 0)
        # Packages in IgnoreErrorsConfig has a mismatched hash in Release AND
        # gitlab-runner_14.8.1_amd64.deb has conflicting stanzas in Packages
        pkg_url = f"{self.base_url}/dists/bullseye/main/binary-amd64/Packages"
        deb_14_8_1 = (
            f"{self.base_url}/pool/bullseye/main/g/gitlab-runner/"
            "gitlab-runner_14.8.1_amd64.deb"
        )
        self.assertTrue(
            any(line.startswith(f"HASH_MISMATCH {pkg_url} (") for line in lines)
        )
        self.assertTrue(
            any(line.startswith(f"HASH_MISMATCH {deb_14_8_1} (") for line in lines)
        )
        self.assertEqual(len(lines), len(set(lines)))

        # With ignore_errors configured for 14.8.1, it is skipped
        sources_list_ignore = self._write_sources_list(
            f"deb [arch=amd64] {self.base_url} bullseye main\n"
            f"ignore_errors {self.base_url} "
            "pool/bullseye/main/g/gitlab-runner/gitlab-runner_14.8.1_amd64.deb\n",
            name="mirror_ignore.list",
        )
        rc2, stdout2, _ = self._run_cli(str(sources_list_ignore))
        self.assertEqual(rc2, 1)
        lines2 = [line for line in stdout2.strip().splitlines() if line]
        self.assertFalse(any(deb_14_8_1 in line for line in lines2))
