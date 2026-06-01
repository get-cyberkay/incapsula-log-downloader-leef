import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(REPO_ROOT, "script")
sys.path.insert(0, SCRIPT_DIR)

from Config import Config  # noqa: E402


SETTINGS_CONFIG = """[SETTINGS]
IMPERVA_API_ID=123456789
IMPERVA_API_KEY=xxxxx-xxxxx-xxxxx-xxxxx
IMPERVA_API_URL=https://logs1.incapsula.com/123456_456789/
IMPERVA_INCOMING_DIR=runtime/incoming
IMPERVA_PROCESS_DIR=runtime/process
IMPERVA_ARCHIVE_DIR=runtime/archive
IMPERVA_USE_PROXY=NO
IMPERVA_PROXY_SERVER=
IMPERVA_USE_CUSTOM_CA_FILE=NO
IMPERVA_CUSTOM_CA_FILE=
IMPERVA_SYSLOG_ENABLE=YES
IMPERVA_SYSLOG_CUSTOM=NO
IMPERVA_SYSLOG_ADDRESS=127.0.0.1
IMPERVA_SYSLOG_PORT=5514
IMPERVA_SYSLOG_PROTO=TCP
SYSLOG_TCP_FRAMING=newline
IMPERVA_SYSLOG_FORMAT=LEEF
IMPERVA_SYSLOG_SECURE=NO
IMPERVA_SYSLOG_SENDER_HOSTNAME=incapsula_waf
IMPERVA_SPLUNK_HEC=NO
IMPERVA_SPLUNK_HEC_IP=
IMPERVA_SPLUNK_HEC_PORT=
IMPERVA_SPLUNK_HEC_TOKEN=
IMPERVA_SPLUNK_HEC_SRC_HOSTNAME=
IMPERVA_SPLUNK_HEC_INDEX=imperva
IMPERVA_SPLUNK_HEC_SOURCE=log_downloader
IMPERVA_SPLUNK_HEC_SOURCETYPE=imperva:cef
"""


class ConfigTests(unittest.TestCase):
    def test_empty_archive_env_disables_archive_retention(self):
        with tempfile.TemporaryDirectory() as config_dir:
            with open(os.path.join(config_dir, "Settings.Config"), "w", encoding="utf-8") as fp:
                fp.write(SETTINGS_CONFIG)

            logger = logging.getLogger("test_empty_archive_env")
            logger.handlers[:] = []
            logger.addHandler(logging.NullHandler())

            with patch.dict(os.environ, {"IMPERVA_ARCHIVE_DIR": ""}, clear=True):
                config = Config(config_dir, logger).read()

        self.assertIs(config.ARCHIVE_DIR, False)


if __name__ == "__main__":
    unittest.main()
