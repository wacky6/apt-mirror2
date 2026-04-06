import asyncio
import contextlib
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from apt_mirror.download import Downloader, DownloadFile, HashSum, HashType
from apt_mirror.download.downloader import DownloaderSettings
from tests.base import BaseTest


class TestVerifyHashCheck(BaseTest):
    def setUp(self):
        super().setUp()
        self._tmp_dir_obj = TemporaryDirectory()
        self.tmp_dir = Path(self._tmp_dir_obj.name)

    def tearDown(self):
        self._tmp_dir_obj.cleanup()
        super().tearDown()

    def test_check_hash(self):
        asyncio.run(self._test_check_hash_logic())

    async def _test_check_hash_logic(self):
        # Setup
        file_path = self.tmp_dir / "test_file"
        content = b"test-content-for-hash"
        with open(file_path, "wb") as f:
            f.write(content)

        expected_md5 = hashlib.md5(content).hexdigest()

        # Mock Settings
        settings = MagicMock(spec=DownloaderSettings)
        settings.check_local_hash = True
        settings.target_root_path = self.tmp_dir
        settings.url = "http://example.com"
        settings.semaphore = asyncio.Semaphore(1)

        # Mock Downloader
        class TestDownloader(Downloader):
            def __post_init__(self):
                self._log = MagicMock()

            def stream(self, source_path):
                return MagicMock()

        downloader = TestDownloader(settings=settings)

        # Create DownloadFile
        download_file = DownloadFile.from_path(Path("test_file"))
        download_file.add_compression_variant(
            Path("test_file"),
            size=len(content),
            hash_sum=HashSum(type=HashType.MD5, hash=expected_md5),
        )

        variants = list(download_file.iter_variants())

        # Test Correct Hash
        downloader._hash_mismatch_count = 0
        result = await downloader._check_hash(file_path, variants)
        self.assertTrue(result, "Should return True for matching hash")
        self.assertEqual(
            downloader._hash_mismatch_count, 0, "Mismatch count should be 0 for match"
        )

        # Test Mismatch
        wrong_hash = "a" * 64
        download_file_wrong = DownloadFile.from_path(Path("test_file"))
        download_file_wrong.add_compression_variant(
            Path("test_file"),
            size=len(content),
            hash_sum=HashSum(type=HashType.SHA256, hash=wrong_hash),
        )
        variants_wrong = list(download_file_wrong.iter_variants())

        downloader._hash_mismatch_count = 0
        result_wrong = await downloader._check_hash(file_path, variants_wrong)
        self.assertFalse(result_wrong, "Should return False for mismatching hash")
        self.assertEqual(
            downloader._hash_mismatch_count, 1, "Mismatch count should increment"
        )

        # Test Config Off
        downloader._settings.check_local_hash = False
        result_off = await downloader._check_hash(file_path, variants)
        self.assertFalse(result_off, "Should return False when config is off")

    def test_self_healing(self):
        asyncio.run(self._test_self_healing_logic())

    async def _test_self_healing_logic(self):
        # Setup: Two paths for the same file (variant).
        # Path 1: "main.deb" (Missing)
        # Path 2: "backup.deb" (Exists and Valid)

        main_path = self.tmp_dir / "main.deb"
        backup_path = self.tmp_dir / "backup.deb"

        content = b"self-healing-content"
        expected_hash = hashlib.sha256(content).hexdigest()

        # Create backup file only
        with open(backup_path, "wb") as f:
            f.write(content)

        # Ensure main file is missing
        if main_path.exists():
            main_path.unlink()

        # Mock Settings
        settings = MagicMock(spec=DownloaderSettings)
        settings.check_local_hash = True
        settings.target_root_path = self.tmp_dir
        settings.url = "http://example.com"
        settings.semaphore = asyncio.Semaphore(1)
        # Mock aiofile factory to support open
        # (needed if download triggers,
        # but we expect it NOT to trigger network download)
        settings.aiofile_factory = MagicMock()

        # Mock Downloader
        @contextlib.asynccontextmanager
        async def mock_stream(source_path):
            yield MagicMock()

        class TestDownloader(Downloader):
            def __post_init__(self):
                self._log = MagicMock()

            def stream(self, source_path):
                return mock_stream(source_path)

        downloader = TestDownloader(settings=settings)

        # Create DownloadFile with one variant that has multiple paths
        download_file = DownloadFile.from_path(Path("main.deb"))

        # We need to inject a variant that returns multiple paths.
        # Since DownloadFile constructs variants internally,
        # we can construct one manually or mock it.
        # Let's mock the variant to return two paths.

        variant = MagicMock()
        variant.size = len(content)
        variant.hashes = {HashType.SHA256: HashSum(HashType.SHA256, expected_hash)}
        variant.get_all_paths.return_value = [Path("main.deb"), Path("backup.deb")]

        # Inject this variant into download_file
        # DownloadFile.iter_variants yields from self.compression_variants.values()
        download_file.iter_variants = MagicMock(return_value=[variant])

        # Execute download_file
        await downloader.download_file(download_file)

        # Verify
        # 1. main.deb should now exist (restored from backup.deb)
        self.assertTrue(main_path.exists(), "Main path should be restored")
        with open(main_path, "rb") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, content, "Restored content should match")

        # 2. Log should mention self-healing
        downloader._log.info.assert_called()
        log_args = [call.args[0] for call in downloader._log.info.call_args_list]
        self.assertTrue(
            any("Self-healed" in arg for arg in log_args),
            f"Log should contain 'Self-healed', got: {log_args}",
        )

        # 3. Stats should prevent re-download
        self.assertEqual(downloader._unmodified_count, 1)
        self.assertEqual(downloader._downloaded_count, 0)

    @patch("asyncio.sleep")
    def test_verify_all_variants_downloaded(self, mock_sleep):
        asyncio.run(self._test_verify_all_variants_downloaded_logic())

    async def _test_verify_all_variants_downloaded_logic(self):
        # Setup: One metadata file with 3 compression variants.
        # We want to ensure the downloader attempts to download all 3,
        # and doesn't just stop after the first.

        # Mock Settings
        settings = MagicMock(spec=DownloaderSettings)
        settings.check_local_hash = False
        settings.target_root_path = self.tmp_dir
        settings.url = "http://example.com"
        settings.semaphore = asyncio.Semaphore(1)

        # We need a mock aiofile factory that records what paths were opened
        opened_paths = []

        class MockAioFile:
            async def write(self, data):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        class MockAioFileFactory:
            def open(self, path):
                opened_paths.append(path.name)
                return MockAioFile()

        settings.aiofile_factory = MockAioFileFactory()

        class MockSlowRateProtector:
            def rate(self, size):
                pass

        class MockSlowRateProtectorFactory:
            def for_target(self, target):
                return MockSlowRateProtector()

        settings.slow_rate_protector_factory = MockSlowRateProtectorFactory()
        settings.rate_limiter = None

        # Mock Downloader
        class MockResponse:
            def __init__(self, size):
                self.size = size
                self.error = None
                self.missing = False
                self.retry = False
                self.date = None

            async def stream(self):
                yield b"content"

        @contextlib.asynccontextmanager
        async def mock_stream(source_path):
            # We'll return a valid stream for each variant
            if source_path.name.endswith((".xz", ".gz", ".bz2")):
                yield MockResponse(7)
            else:
                yield MockResponse(0)

        class TestDownloader(Downloader):
            def __post_init__(self):
                self._log = MagicMock()

            def stream(self, source_path):
                return mock_stream(source_path)

        downloader = TestDownloader(settings=settings)

        # Create DownloadFile with 3 variants
        download_file = DownloadFile.from_path(Path("Packages"), ignore_missing=True)
        download_file.ignore_errors = True
        download_file.add_compression_variant(Path("Packages.xz"), size=7)
        download_file.add_compression_variant(Path("Packages.gz"), size=7)
        download_file.add_compression_variant(Path("Packages.bz2"), size=7)

        # Execute download_file
        await downloader.download_file(download_file)

        self.assertIn("Packages.xz", opened_paths)
        self.assertIn("Packages.gz", opened_paths)
        self.assertIn("Packages.bz2", opened_paths)
        self.assertEqual(len(opened_paths), 4)  # 3 compressed + 1 uncompressed
        self.assertEqual(downloader._downloaded_count, 4)
        self.assertEqual(downloader._downloaded_size, 28)
