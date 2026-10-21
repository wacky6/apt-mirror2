import asyncio
import gzip
import hashlib
import os
from collections.abc import Iterable, Sequence
from contextlib import asynccontextmanager, contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

import httpx

from apt_mirror.download import DownloadFile, FileCompression, HashSum, HashType
from apt_mirror.download.downloader import (
    Downloader,
    DownloaderSettings,
)
from apt_mirror.download.protocols.ftp import FTPDownloader
from apt_mirror.download.protocols.http import HTTPDownloader
from apt_mirror.download.proxy import Proxy
from apt_mirror.download.response import DownloadResponse
from apt_mirror.download.slow_rate_protector import (
    SlowRateException,
    SlowRateProtector,
    SlowRateProtectorFactory,
)
from apt_mirror.download.url import URL
from tests.base import BaseTest

if TYPE_CHECKING:
    from apt_mirror.aiofile import BaseAsyncIOFileWriterFactory
else:
    BaseAsyncIOFileWriterFactory = object


class TestDownload(BaseTest):
    def test_download_file_size(self):
        file_path = Path("/tmp/t")
        file = DownloadFile.from_hashed_path(
            file_path, 1024, HashSum(HashType.MD5, ""), use_by_hash=True
        )
        file.add_compression_variant(file_path.with_suffix(".bz2"), 512)
        file.add_compression_variant(file_path.with_suffix(".xz"), 777)
        file.add_compression_variant(file_path.with_suffix(".gz"), 256)

        self.assertEqual(file.size, 777)

    def test_slow_rate_protector(self):
        with patch(f"{SlowRateProtector.__module__}.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 0, 0)

            protector = SlowRateProtector("test", 60, 100)
            protector.rate(1)

            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 0, 59)
            protector.rate(1)

            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 1, 0)
            with self.assertRaises(SlowRateException):
                protector.rate(1)

            with self.assertRaises(SlowRateException):
                protector.rate(100 * 60 - 4)

            protector.rate(1)


class TestDownloader(IsolatedAsyncioTestCase):
    CONTENTS = [
        {
            "data": (b"hello", b"world!"),
            "hashes": {
                HashSum(
                    HashType.SHA512,
                    "4e6be41aade78bebbe95662312b581088bd860320ed99cfbe5ae8ab8cf355e95f6bac60220bb0dee2d66613111c18f8ce08319d014fbc07e74001693172551c1",
                ),
                HashSum(
                    HashType.SHA256,
                    "98d234db7e91f5ba026a25d0d6f17bc5ee0a347ea2216b0c9de06d43536d49f4",
                ),
                HashSum(
                    HashType.SHA1,
                    "3c608e47152c7b175e9d3c171002dc234bb00953",
                ),
                HashSum(
                    HashType.MD5,
                    "420e57b017066b44e05ea1577f6e2e12",
                ),
            },
        }
    ]

    class _AIOFileWriterFactory(BaseAsyncIOFileWriterFactory):
        class _AIOFileWriter:
            def __init__(self, path: Path):
                self._fp = path.open("wb")

            async def write(self, data: bytes) -> int:
                return self._fp.write(data)

            def close(self):
                self._fp.close()

        @asynccontextmanager
        async def open(self, path: Path):
            writer = self._AIOFileWriter(path)
            try:
                yield writer
            finally:
                writer.close()

        async def test_storage(self, *test_paths: Path): ...

    class _Downloader(Downloader):
        RETRY_TIMEOUT = 0

        def __init__(self, *, settings: DownloaderSettings):
            super().__init__(settings=settings)
            self.response_chunks: Sequence[bytes] = []
            self.response = DownloadResponse(_stream=self.response_stream, size=0)

        async def response_stream(self):
            for chunk in self.response_chunks:
                yield chunk

        def set_response(self, *data: bytes):
            self.response_chunks = data
            self.response.size = sum(len(p) for p in data)

        @asynccontextmanager
        async def stream(self, source_path: Path):
            yield self.response

    @contextmanager
    def get_downloader(self, check_hashes: set[HashType] | None = None):
        if not check_hashes:
            check_hashes = {t for t in HashType}

        with TemporaryDirectory() as tmpdir:
            yield self._Downloader(
                settings=DownloaderSettings(
                    url=URL.from_string("http://localhost.local/repo"),
                    target_root_path=Path(tmpdir),
                    aiofile_factory=self._AIOFileWriterFactory(),
                    proxy=Proxy(False, None, None, None, None),
                    http2_disable=False,
                    user_agent="apt-mirror2-test",
                    semaphore=asyncio.Semaphore(1),
                    slow_rate_protector_factory=SlowRateProtectorFactory(False, 0, 0),
                    check_hashes=check_hashes,
                )
            )

    def get_download_file(self, path: Path, size: int, hash_sums: Iterable[HashSum]):
        download_file = DownloadFile.from_path(path)

        for hash_sum in hash_sums:
            download_file.add_compression_variant(
                path,
                size,
                hash_sum,
            )

        return download_file

    async def test_download_file(self):
        file_path = Path("dists/test/InRelease")
        content = self.CONTENTS[0]["data"]

        with self.get_downloader() as downloader:
            downloader.set_response(*content)
            content = b"".join(content)

            source_file = self.get_download_file(file_path, len(content), [])

            await downloader.download_file(source_file)

            self.assertEqual(downloader.downloaded_files_count, 1)
            self.assertEqual(downloader.downloaded_files_size, len(content))
            self.assertFalse(downloader.has_errors())
            self.assertFalse(downloader.has_missing())
            self.assertEqual(
                (downloader.get_target_root_path() / file_path).read_bytes(),
                content,
            )

    async def test_download_hashes(self):
        file_path = Path("dists/test/InRelease")
        content: tuple[bytes] = self.CONTENTS[0]["data"]
        content_hashes: set[HashSum] = self.CONTENTS[0]["hashes"]

        with self.get_downloader() as downloader:
            downloader.set_response(*content)
            content_bytes = b"".join(content)

            source_file = self.get_download_file(
                file_path,
                len(content_bytes),
                (),
            )

            await downloader.download_file(source_file)

            self.assertEqual(downloader.downloaded_files_count, 1)
            self.assertEqual(downloader.downloaded_files_size, len(content_bytes))
            self.assertFalse(downloader.has_errors())
            self.assertFalse(downloader.has_missing())
            self.assertEqual(
                (downloader.get_target_root_path() / file_path).read_bytes(),
                content_bytes,
            )

            downloader.reset_stats()
            (downloader.get_target_root_path() / file_path).unlink()

            broken_hashes = deepcopy(content_hashes)
            for h in broken_hashes:
                if h.type == HashType.MD5:
                    h.hash = "broken"
                    break

            source_file = self.get_download_file(
                file_path,
                len(content_bytes),
                broken_hashes,
            )

            await downloader.download_file(source_file)

            self.assertEqual(downloader.downloaded_files_count, 0)
            self.assertEqual(downloader.downloaded_files_size, 0)
            self.assertTrue(downloader.has_errors())
            self.assertFalse(downloader.has_missing())
            self.assertTrue((downloader.get_target_root_path() / file_path).exists())

        with self.get_downloader(check_hashes={HashType.SHA512}) as downloader:
            downloader.set_response(*content)
            content_bytes = b"".join(content)

            broken_hashes = content_hashes.copy()
            for h in broken_hashes:
                if h.type == HashType.MD5:
                    h.hash = "broken"
                    break

            source_file = self.get_download_file(
                file_path,
                len(content_bytes),
                content_hashes,
            )

            await downloader.download_file(source_file)

            self.assertEqual(downloader.downloaded_files_count, 1)
            self.assertEqual(downloader.downloaded_files_size, len(content_bytes))
            self.assertFalse(downloader.has_errors())
            self.assertFalse(downloader.has_missing())
            self.assertEqual(
                (downloader.get_target_root_path() / file_path).read_bytes(),
                content_bytes,
            )

    async def test_sum_file_hash_cache(self):
        file_path = Path("dists/test/InRelease")
        content: tuple[bytes] = self.CONTENTS[0]["data"]
        content_hashes: set[HashSum] = self.CONTENTS[0]["hashes"]
        content_bytes = b"".join(content)

        expected_sha256 = next(
            h for h in content_hashes if h.type == HashType.SHA256
        ).hash

        with self.get_downloader(check_hashes={HashType.SHA256}) as downloader:
            downloader.set_response(*content)

            source_file = self.get_download_file(
                file_path,
                len(content_bytes),
                content_hashes,
            )

            downloader._settings.check_local_hash = True

            # 1. Fresh download - file missing -> downloads -> sets sum file
            await downloader.download_file(source_file)
            self.assertEqual(downloader.downloaded_files_count, 1)

            # verify sum file was created with correct content
            target_path = downloader._settings.target_root_path / file_path
            sum_path = target_path.parent / f".{target_path.name}.sum"
            self.assertTrue(sum_path.exists())
            self.assertIn(f"sha256:{expected_sha256.lower()}", sum_path.read_text())

            # 2. Local check cache hit
            downloader.reset_stats()
            # The file is physically on disk now, and the sum file matches.

            await downloader.download_file(source_file)

            # check_local_hash=True and sum matches, so it skips the download.
            # unmodified files + 1
            self.assertEqual(downloader.unmodified_files_count, 1)
            self.assertEqual(downloader.downloaded_files_count, 0)

    def _make_settings(
        self,
        tmpdir: str,
        url: str = "http://localhost.local/repo",
        semaphore: asyncio.Semaphore | None = None,
        check_hashes: set[HashType] | None = None,
    ) -> DownloaderSettings:
        if check_hashes is None:
            check_hashes = set(HashType)

        return DownloaderSettings(
            url=URL.from_string(url),
            target_root_path=Path(tmpdir),
            aiofile_factory=self._AIOFileWriterFactory(),
            proxy=Proxy(False, None, None, None, None),
            http2_disable=False,
            user_agent="apt-mirror2-test",
            semaphore=semaphore or asyncio.Semaphore(1),
            slow_rate_protector_factory=SlowRateProtectorFactory(False, 0, 0),
            check_hashes=check_hashes,
        )

    async def test_http_stream_no_double_yield_on_athrow_or_exit_error(self):
        with TemporaryDirectory() as tmpdir:
            downloader = HTTPDownloader(settings=self._make_settings(tmpdir))
            try:
                exit_error_raised = False

                @asynccontextmanager
                async def fake_httpx_stream(method: str, path: str):
                    nonlocal exit_error_raised
                    response = httpx.Response(
                        200,
                        headers={"Content-Length": "5"},
                        content=b"hello",
                        request=httpx.Request(method, f"http://localhost.local/{path}"),
                    )
                    try:
                        yield response
                    finally:
                        exit_error_raised = True
                        raise httpx.RemoteProtocolError("Connection reset on close")

                downloader._httpx.stream = fake_httpx_stream  # type: ignore

                # 1. Exception thrown inside `async with downloader.stream(...)`
                # must NOT raise `RuntimeError: generator didn't stop after athrow()`
                with self.assertRaises(SlowRateException):
                    async with downloader.stream(Path("dists/test/InRelease")):
                        raise SlowRateException("dists/test/InRelease", "1B/sec")

                self.assertTrue(exit_error_raised)

                # 2. Normal exit when inner `__aexit__` raises must NOT raise
                # `RuntimeError: generator didn't stop`
                async with downloader.stream(Path("dists/test/InRelease")) as resp:
                    self.assertFalse(resp.missing)
                    self.assertIsNone(resp.error)

                # 3. Exception thrown inside `async with` when `stream` yielded an
                # error response must also propagate cleanly without double-yield
                @asynccontextmanager
                async def failing_httpx_stream(method: str, path: str):
                    raise httpx.RemoteProtocolError(
                        "Server disconnected without sending a response."
                    )
                    yield  # pragma: no cover

                downloader._httpx.stream = failing_httpx_stream  # type: ignore
                with self.assertRaises(ValueError):
                    async with downloader.stream(Path("dists/test/InRelease")) as resp:
                        self.assertTrue(resp.retry)
                        raise ValueError("inner failure")
            finally:
                await downloader.aclose()

    async def test_ftp_stream_no_double_yield_on_athrow_or_quit_error(self):
        with TemporaryDirectory() as tmpdir:
            downloader = FTPDownloader(
                settings=self._make_settings(tmpdir, url="ftp://localhost.local/repo")
            )

            mock_ftp = MagicMock()
            mock_ftp.encoding = "utf-8"

            async def fake_change_directory(path):
                return None

            async def fake_stat(path):
                return {"type": "file", "size": "10", "modify": "20240101000000"}

            mock_ftp.change_directory = fake_change_directory
            mock_ftp.stat = fake_stat

            @asynccontextmanager
            async def fake_ftp_context(*args, **kwargs):
                try:
                    yield mock_ftp
                finally:
                    raise ConnectionResetError(104, "Connection reset by peer on QUIT")

            with patch("aioftp.Client.context", fake_ftp_context):
                with self.assertRaises(SlowRateException):
                    async with downloader.stream(Path("dists/test/InRelease")):
                        raise SlowRateException("dists/test/InRelease", "1B/sec")

                self.assertTrue(mock_ftp.close.called)

                async with downloader.stream(Path("dists/test/InRelease")) as resp:
                    self.assertFalse(resp.missing)
                    self.assertIsNone(resp.error)
                    self.assertEqual(resp.size, 10)

    async def test_http_remote_protocol_error_classification(self):
        with TemporaryDirectory() as tmpdir:
            downloader = HTTPDownloader(settings=self._make_settings(tmpdir))
            try:
                # Case 1: Server disconnected on idle keep-alive -> retry=True
                @asynccontextmanager
                async def disconnected_stream(method: str, path: str):
                    raise httpx.RemoteProtocolError(
                        "Server disconnected without sending a response."
                    )
                    yield  # pragma: no cover

                downloader._httpx.stream = disconnected_stream  # type: ignore
                async with downloader.stream(Path("Packages")) as resp:
                    self.assertTrue(resp.retry)
                    self.assertIsNone(resp.error)

                # Case 2: StreamReset / peer closed -> retry=False, error=str(ex)
                @asynccontextmanager
                async def reset_stream(method: str, path: str):
                    raise httpx.RemoteProtocolError(
                        "<StreamReset stream_id:1, error_code:8, remote_reset:True>"
                    )
                    yield  # pragma: no cover

                downloader._httpx.stream = reset_stream  # type: ignore
                async with downloader.stream(Path("Packages")) as resp:
                    self.assertFalse(resp.retry)
                    self.assertIsNotNone(resp.error)
                    self.assertIn("StreamReset", resp.error or "")
            finally:
                await downloader.aclose()

    async def test_http_missing_last_modified_and_gzip_content_encoding(self):
        raw_content = b"package: curl\nversion: 1.0\n"
        gz_content = gzip.compress(raw_content)
        gz_sha256 = hashlib.sha256(gz_content).hexdigest()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("missing"):
                # 404 without Last-Modified header
                return httpx.Response(404, content=b"Not Found")
            # 200 OK without Last-Modified and with Content-Encoding: gzip on a .gz file
            return httpx.Response(
                200,
                headers={
                    "Content-Length": str(len(gz_content)),
                    "Content-Encoding": "gzip",
                },
                stream=httpx.ByteStream(gz_content),
            )

        with TemporaryDirectory() as tmpdir:
            downloader = HTTPDownloader(settings=self._make_settings(tmpdir))
            downloader.RETRY_TIMEOUT = 0
            await downloader._httpx.aclose()
            downloader._httpx = httpx.AsyncClient(
                base_url="http://localhost.local/repo/",
                transport=httpx.MockTransport(handler),
            )
            try:
                # 1. Verify 404 without Last-Modified is treated as missing
                missing_file = DownloadFile.from_path(Path("dists/test/missing"))
                await downloader.download_file(missing_file)
                self.assertTrue(downloader.has_missing())
                self.assertFalse(downloader.has_errors())

                downloader.reset_stats()

                # 2. Verify .gz file with Content-Encoding: gzip and no Last-Modified
                # is written raw without auto-decompression corrupting size/hash
                gz_path = Path("dists/test/main/binary-amd64/Packages.gz")
                dl_file = DownloadFile.from_hashed_path(
                    gz_path,
                    size=len(gz_content),
                    hash_sum=HashSum(HashType.SHA256, gz_sha256),
                    use_by_hash=False,
                )
                # Ensure from_hashed_path did not add a phantom uncompressed variant
                self.assertEqual(
                    list(dl_file.compression_variants.keys()),
                    [FileCompression.GZ],
                )

                await downloader.download_file(dl_file)
                self.assertFalse(downloader.has_errors())
                self.assertEqual(downloader.downloaded_files_count, 1)
                self.assertEqual(
                    (Path(tmpdir) / gz_path).read_bytes(),
                    gz_content,
                )
            finally:
                await downloader.aclose()

    async def test_bounded_retry_on_persistent_server_disconnect(self):
        with TemporaryDirectory() as tmpdir:
            downloader = self._Downloader(settings=self._make_settings(tmpdir))
            downloader.RETRY_TIMEOUT = 0
            downloader.MAX_FREE_RETRIES = 3

            attempts = 0

            @asynccontextmanager
            async def always_retry_stream(source_path: Path):
                nonlocal attempts
                attempts += 1
                yield DownloadResponse(_stream=None, retry=True)

            downloader.stream = always_retry_stream  # type: ignore

            source_file = DownloadFile.from_path(Path("dists/test/InRelease"))
            await downloader.download_file(source_file)

            # 3 free retries + 10 regular tries = 13 total attempts (no infinite loop!)
            self.assertEqual(attempts, 13)
            self.assertTrue(downloader.has_errors())
            self.assertEqual(downloader.error_files_count, 1)

    async def test_mid_stream_connection_reset_recovers_and_releases_semaphore(self):
        content = b"hello world! recovered after reset"
        expected_sha256 = hashlib.sha256(content).hexdigest()

        with TemporaryDirectory() as tmpdir:
            semaphore = asyncio.Semaphore(1)
            downloader = self._Downloader(
                settings=self._make_settings(tmpdir, semaphore=semaphore)
            )
            downloader.RETRY_TIMEOUT = 0

            attempt = 0
            stream_closed_on_abort = False
            semaphore_free_during_sleep: list[bool] = []

            async def failing_then_working_stream():
                nonlocal attempt, stream_closed_on_abort
                attempt += 1
                if attempt == 1:
                    try:
                        yield b"hello "
                        raise httpx.ReadError("Connection reset by peer")
                    finally:
                        stream_closed_on_abort = True
                else:
                    yield content

            @asynccontextmanager
            async def custom_stream(source_path: Path):
                yield DownloadResponse(
                    _stream=failing_then_working_stream,
                    size=len(content),
                )

            downloader.stream = custom_stream  # type: ignore

            orig_sleep = asyncio.sleep

            async def check_sleep(delay):
                # Semaphore must NOT be locked while sleeping between retries
                semaphore_free_during_sleep.append(not semaphore.locked())
                await orig_sleep(0)

            source_file = self.get_download_file(
                Path("pool/main/p/pkg/pkg_1.0.deb"),
                len(content),
                [HashSum(HashType.SHA256, expected_sha256)],
            )

            with patch("apt_mirror.download.downloader.asyncio.sleep", check_sleep):
                await downloader.download_file(source_file)

            self.assertEqual(attempt, 2)
            self.assertTrue(stream_closed_on_abort)
            self.assertEqual(semaphore_free_during_sleep, [True])
            self.assertEqual(downloader.downloaded_files_count, 1)
            self.assertFalse(downloader.has_errors())
            self.assertEqual(
                (Path(tmpdir) / "pool/main/p/pkg/pkg_1.0.deb").read_bytes(),
                content,
            )

    async def test_by_hash_not_blacklisted_by_missing_uncompressed_variant(self):
        xz_content = b"compressed-xz-packages"
        xz_sha256 = hashlib.sha256(xz_content).hexdigest()
        xz_sha512 = hashlib.sha512(xz_content).hexdigest()
        raw_sha256 = hashlib.sha256(b"uncompressed-packages").hexdigest()
        raw_sha512 = hashlib.sha512(b"uncompressed-packages").hexdigest()

        with TemporaryDirectory() as tmpdir:
            downloader = self._Downloader(settings=self._make_settings(tmpdir))
            downloader.RETRY_TIMEOUT = 0

            # Server does not support SHA512 (404), supports SHA256 for .xz,
            # and does NOT serve uncompressed Packages at all (404 everywhere).
            @asynccontextmanager
            async def mock_stream(source_path: Path):
                if str(source_path).endswith(xz_sha256):
                    yield DownloadResponse(
                        _stream=lambda: self._async_iter([xz_content]),
                        size=len(xz_content),
                    )
                else:
                    yield DownloadResponse(_stream=None, missing=True)

            downloader.stream = mock_stream  # type: ignore

            dl_file = DownloadFile.from_hashed_path(
                Path("dists/test/main/binary-amd64/Packages.xz"),
                size=len(xz_content),
                hash_sum=HashSum(HashType.SHA512, xz_sha512),
                use_by_hash=True,
            )
            dl_file.add_compression_variant(
                Path("dists/test/main/binary-amd64/Packages.xz"),
                size=len(xz_content),
                hash_sum=HashSum(HashType.SHA256, xz_sha256),
                use_by_hash=True,
            )
            # Also add uncompressed Packages variant (404 on mirror)
            dl_file.add_compression_variant(
                Path("dists/test/main/binary-amd64/Packages"),
                size=21,
                hash_sum=HashSum(HashType.SHA512, raw_sha512),
                use_by_hash=True,
            )
            dl_file.add_compression_variant(
                Path("dists/test/main/binary-amd64/Packages"),
                size=21,
                hash_sum=HashSum(HashType.SHA256, raw_sha256),
                use_by_hash=True,
            )

            await downloader.download_file(dl_file)

            self.assertEqual(downloader.downloaded_files_count, 1)
            self.assertFalse(downloader.has_errors())
            self.assertFalse(downloader.has_missing())
            # SHA512 returned 404 on .xz which then succeeded via SHA256 -> blacklisted
            self.assertIn(HashType.SHA512, downloader._unsupported_by_hash_algos)
            # SHA256 succeeded on .xz and must NOT be blacklisted by missing Packages
            self.assertNotIn(HashType.SHA256, downloader._unsupported_by_hash_algos)
            self.assertIn(HashType.SHA256, downloader._supported_by_hash_algos)

    async def test_need_update_preserves_existing_unmodified_file(self):
        content = b"existing-unmodified-content"
        mtime = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        file_path = Path("dists/test/Release")

        with TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / file_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            os.utime(target, (mtime.timestamp(), mtime.timestamp()))

            downloader = self._Downloader(settings=self._make_settings(tmpdir))
            stream_read_called = False

            async def fail_if_read():
                nonlocal stream_read_called
                stream_read_called = True
                yield content

            @asynccontextmanager
            async def mock_stream(source_path: Path):
                yield DownloadResponse(
                    _stream=fail_if_read,
                    size=len(content),
                    date=mtime,
                )

            downloader.stream = mock_stream  # type: ignore

            source_file = DownloadFile.from_path(file_path)
            await downloader.download_file(source_file)

            self.assertFalse(stream_read_called)
            self.assertEqual(downloader.unmodified_files_count, 1)
            self.assertEqual(downloader.downloaded_files_count, 0)
            self.assertTrue(target.exists())
            self.assertEqual(target.read_bytes(), content)

    async def test_http_error_response_body_drained_on_exit(self):
        with TemporaryDirectory() as tmpdir:
            downloader = HTTPDownloader(settings=self._make_settings(tmpdir))
            try:
                raw_chunks_drained = 0

                class FakeErrorResponse:
                    is_client_error = True
                    is_server_error = False
                    status_code = 404
                    headers = {"Content-Length": "9"}
                    is_stream_consumed = False
                    is_closed = False

                    async def aiter_raw(self, chunk_size=None):
                        nonlocal raw_chunks_drained
                        self.is_stream_consumed = True
                        raw_chunks_drained += 1
                        yield b"Not Found"

                @asynccontextmanager
                async def fake_stream(method: str, path: str):
                    yield FakeErrorResponse()

                downloader._httpx.stream = fake_stream  # type: ignore

                async with downloader.stream(Path("dists/test/missing")) as resp:
                    self.assertTrue(resp.missing)
                    # Caller does not read resp.stream() on 404

                # Exiting downloader.stream() must have drained the 404 body
                self.assertEqual(raw_chunks_drained, 1)
            finally:
                await downloader.aclose()

    async def test_aiofile_factory_closes_file_on_exit(self):
        from apt_mirror.aiofile import AsyncIOFileFactory

        with TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.bin"
            factory = await AsyncIOFileFactory.create(test_file)
            async with factory.open(test_file) as fp:
                await fp.write(b"abc")
            self.assertEqual(test_file.read_bytes(), b"abc")

    async def test_download_captures_unhandled_task_exceptions(self):
        with TemporaryDirectory() as tmpdir:
            downloader = self._Downloader(settings=self._make_settings(tmpdir))

            async def crashing_download_file(source_file: DownloadFile):
                raise RuntimeError("unexpected crash")

            downloader.download_file = crashing_download_file  # type: ignore
            downloader.add(DownloadFile.from_path(Path("dists/test/InRelease")))
            await downloader.download()

            self.assertTrue(downloader.has_errors())
            self.assertEqual(downloader.error_files_count, 1)

    @staticmethod
    async def _async_iter(chunks: list[bytes]):
        for chunk in chunks:
            yield chunk
