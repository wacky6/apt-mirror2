from pathlib import Path
from tempfile import TemporaryDirectory

from apt_mirror.apt_mirror import PathCleaner
from tests.base import BaseTest


class TestCleanSum(BaseTest):
    def setUp(self):
        super().setUp()
        self._tmp_dir_obj = TemporaryDirectory()
        self.tmp_dir = Path(self._tmp_dir_obj.name)

    def tearDown(self):
        self._tmp_dir_obj.cleanup()
        super().tearDown()

    def test_clean_sum_preservation(self):
        # Create needed file and its .sum file
        needed_file = self.tmp_dir / "needed.deb"
        needed_file.write_text("needed content")
        needed_sum = self.tmp_dir / ".needed.deb.sum"
        needed_sum.write_text("needed hash")

        # Create unneeded file and its .sum file
        unneeded_file = self.tmp_dir / "unneeded.deb"
        unneeded_file.write_text("unneeded content")
        unneeded_sum = self.tmp_dir / ".unneeded.deb.sum"
        unneeded_sum.write_text("unneeded hash")

        # Create an unrelated hidden file that should still be cleaned
        other_hidden = self.tmp_dir / ".random_hidden"
        other_hidden.write_text("random")

        keep_files = {Path("needed.deb")}

        # We don't need ratios for this test
        cleaner = PathCleaner(self.tmp_dir, keep_files)

        files_to_remove = {f.relative_to(self.tmp_dir) for f in cleaner._files_queue}

        # needed.deb should NOT be in removal queue
        self.assertNotIn(Path("needed.deb"), files_to_remove)
        # .needed.deb.sum should NOT be in removal queue (this is the fix)
        self.assertNotIn(Path(".needed.deb.sum"), files_to_remove)

        # unneeded.deb SHOULD be in removal queue
        self.assertIn(Path("unneeded.deb"), files_to_remove)
        # .unneeded.deb.sum SHOULD be in removal queue
        self.assertIn(Path(".unneeded.deb.sum"), files_to_remove)
        # .random_hidden SHOULD be in removal queue
        self.assertIn(Path(".random_hidden"), files_to_remove)

    def test_clean_sum_in_subfolder(self):
        # Create a subfolder with a kept file and its .sum file
        subfolder = self.tmp_dir / "pool/main/a/app"
        subfolder.mkdir(parents=True)

        needed_file = subfolder / "app_1.0.deb"
        needed_file.write_text("content")
        needed_sum = subfolder / ".app_1.0.deb.sum"
        needed_sum.write_text("hash")

        keep_files = {Path("pool/main/a/app/app_1.0.deb")}

        cleaner = PathCleaner(self.tmp_dir, keep_files)
        files_to_remove = {f.relative_to(self.tmp_dir) for f in cleaner._files_queue}

        self.assertNotIn(Path("pool/main/a/app/app_1.0.deb"), files_to_remove)
        self.assertNotIn(Path("pool/main/a/app/.app_1.0.deb.sum"), files_to_remove)
