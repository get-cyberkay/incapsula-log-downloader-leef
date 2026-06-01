import logging
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(REPO_ROOT, "script")
sys.path.insert(0, SCRIPT_DIR)

from LogsDownloader import LogsDownloader  # noqa: E402


class LogsDownloaderDirectoryTests(unittest.TestCase):
    def test_false_archive_dir_is_not_checked_as_a_filesystem_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = os.path.join(temp_dir, "config")
            system_log_dir = os.path.join(temp_dir, "system-logs")
            incoming_dir = os.path.join(temp_dir, "incoming")
            process_dir = os.path.join(temp_dir, "process")
            os.makedirs(config_dir)

            config = SimpleNamespace(
                INCOMING_DIR=incoming_dir,
                PROCESS_DIR=process_dir,
                ARCHIVE_DIR=False,
                SYSLOG_ENABLE="NO",
                SPLUNK_HEC="NO",
            )

            logger = logging.getLogger("test_false_archive_dir")
            logger.handlers[:] = []
            logger.addHandler(logging.NullHandler())

            exists_calls = []
            real_exists = os.path.exists

            def tracked_exists(path):
                exists_calls.append(path)
                return real_exists(path)

            with patch("LogsDownloader.Config") as config_class, \
                    patch("LogsDownloader.FileDownloader"), \
                    patch("LogsDownloader.LastFileId"), \
                    patch("LogsDownloader.LogsFileIndex"), \
                    patch("LogsDownloader.os.path.exists", side_effect=tracked_exists):
                config_class.return_value.read.return_value = config
                LogsDownloader(config_dir, system_log_dir, "ERROR")

        self.assertNotIn(False, exists_calls)


if __name__ == "__main__":
    unittest.main()
