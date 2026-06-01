import logging
import os
import socket
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(REPO_ROOT, "script")
sys.path.insert(0, SCRIPT_DIR)

from HandlingLogs import HandlingLogs  # noqa: E402


class TcpReceiver:
    def __init__(self):
        self.ready = threading.Event()
        self.received = []
        self.errors = []
        self.port = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        self.ready.wait(5)
        if self.errors:
            raise self.errors[0]

    def join(self):
        self.thread.join(5)
        if self.thread.is_alive():
            raise AssertionError("TCP receiver did not finish")
        if self.errors:
            raise self.errors[0]

    def payload(self):
        return b"".join(self.received).decode("utf-8")

    def _run(self):
        server = None
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            self.port = server.getsockname()[1]
            server.listen(1)
            self.ready.set()
            connection, _ = server.accept()
            with connection:
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    self.received.append(chunk)
        except Exception as exc:
            self.errors.append(exc)
            self.ready.set()
        finally:
            if server is not None:
                server.close()


class SyslogLineDeliveryTests(unittest.TestCase):
    def test_tcp_newline_framing_sends_each_log_as_separate_line(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            process_dir = os.path.join(temp_dir, "process")
            os.makedirs(process_dir)
            log_file = "8998261271655_1.log"
            with open(os.path.join(process_dir, log_file), "w", encoding="utf-8") as fp:
                fp.write('{"message":"first log","timestamp":1710000000000,"host":{"name":"site-a"}}\n')
                fp.write('{"message":"second log","timestamp":1710000001000,"host":{"name":"site-b"}}\n')

            receiver = TcpReceiver()
            receiver.start()

            logger = logging.getLogger("test_tcp_newline_framing")
            logger.handlers[:] = []
            logger.addHandler(logging.NullHandler())

            config = SimpleNamespace(
                PROCESS_DIR=process_dir,
                ARCHIVE_DIR="",
                config_path=temp_dir,
                SYSLOG_PROTO="TCP",
                SYSLOG_ENABLE="YES",
                SYSLOG_CUSTOM="NO",
                SYSLOG_FORMAT="JSON",
                SYSLOG_TCP_FRAMING="newline",
                SYSLOG_ADDRESS="127.0.0.1",
                SYSLOG_PORT=str(receiver.port),
                IMPERVA_SYSLOG_SECURE="NO",
                SYSLOG_SENDER_HOSTNAME="incapsula_waf",
                SPLUNK_HEC="NO",
            )

            result = HandlingLogs(config, logger).send_file(log_file)
            receiver.join()

            lines = receiver.payload().splitlines()
            self.assertEqual((True, log_file), result)
            self.assertEqual(2, len(lines), receiver.payload())
            self.assertIn('"message":"first log"', lines[0])
            self.assertIn('"message":"second log"', lines[1])

    def test_leef_tcp_newline_framing_sends_records_without_syslog_prefix(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            process_dir = os.path.join(temp_dir, "process")
            os.makedirs(process_dir)
            log_file = "8998261271655_2.log"
            with open(os.path.join(process_dir, log_file), "w", encoding="utf-8") as fp:
                fp.write('{"message":"first leef log","timestamp":1710000000000,"host":{"name":"site-a"}}\n')
                fp.write('{"message":"second leef log","timestamp":1710000001000,"host":{"name":"site-b"}}\n')

            receiver = TcpReceiver()
            receiver.start()

            logger = logging.getLogger("test_leef_tcp_newline_framing")
            logger.handlers[:] = []
            logger.addHandler(logging.NullHandler())

            config = SimpleNamespace(
                PROCESS_DIR=process_dir,
                ARCHIVE_DIR="",
                config_path=temp_dir,
                SYSLOG_PROTO="TCP",
                SYSLOG_ENABLE="YES",
                SYSLOG_CUSTOM="NO",
                SYSLOG_FORMAT="LEEF",
                SYSLOG_TCP_FRAMING="newline",
                SYSLOG_ADDRESS="127.0.0.1",
                SYSLOG_PORT=str(receiver.port),
                IMPERVA_SYSLOG_SECURE="NO",
                SYSLOG_SENDER_HOSTNAME="incapsula_waf",
                SPLUNK_HEC="NO",
            )

            result = HandlingLogs(config, logger).send_file(log_file)
            receiver.join()

            lines = receiver.payload().splitlines()
            self.assertEqual((True, log_file), result)
            self.assertEqual(2, len(lines), receiver.payload())
            self.assertTrue(lines[0].startswith("LEEF:2.0|"), lines[0])
            self.assertTrue(lines[1].startswith("LEEF:2.0|"), lines[1])
            self.assertNotIn("<30>", lines[0])
            self.assertIn("message=first leef log", lines[0])
            self.assertIn("message=second leef log", lines[1])

    def test_pretty_json_array_is_ingested_as_one_message_per_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            process_dir = os.path.join(temp_dir, "process")
            os.makedirs(process_dir)
            log_file = "8998261271655_3.log"
            with open(os.path.join(process_dir, log_file), "w", encoding="utf-8") as fp:
                fp.write(
                    """[
  {
    "message": "first array log",
    "timestamp": 1710000000000,
    "host": {
      "name": "site-a"
    }
  },
  {
    "message": "second array log",
    "timestamp": 1710000001000,
    "host": {
      "name": "site-b"
    }
  }
]
"""
                )

            receiver = TcpReceiver()
            receiver.start()

            logger = logging.getLogger("test_pretty_json_array_ingestion")
            logger.handlers[:] = []
            logger.addHandler(logging.NullHandler())

            config = SimpleNamespace(
                PROCESS_DIR=process_dir,
                ARCHIVE_DIR="",
                config_path=temp_dir,
                SYSLOG_PROTO="TCP",
                SYSLOG_ENABLE="YES",
                SYSLOG_CUSTOM="NO",
                SYSLOG_FORMAT="LEEF",
                SYSLOG_TCP_FRAMING="newline",
                SYSLOG_ADDRESS="127.0.0.1",
                SYSLOG_PORT=str(receiver.port),
                IMPERVA_SYSLOG_SECURE="NO",
                SYSLOG_SENDER_HOSTNAME="incapsula_waf",
                SPLUNK_HEC="NO",
            )

            result = HandlingLogs(config, logger).send_file(log_file)
            receiver.join()

            lines = receiver.payload().splitlines()
            self.assertEqual((True, log_file), result)
            self.assertEqual(2, len(lines), receiver.payload())
            self.assertTrue(lines[0].startswith("LEEF:2.0|"), lines[0])
            self.assertTrue(lines[1].startswith("LEEF:2.0|"), lines[1])
            self.assertIn("message=first array log", lines[0])
            self.assertIn("message=second array log", lines[1])


if __name__ == "__main__":
    unittest.main()
