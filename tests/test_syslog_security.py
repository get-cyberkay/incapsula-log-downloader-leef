import logging
import os
import socket
import sys
import unittest
from unittest import mock


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(REPO_ROOT, "script")
sys.path.insert(0, SCRIPT_DIR)

from SyslogClient import SyslogClient  # noqa: E402


def _silent_logger(name):
    logger = logging.getLogger(name)
    logger.handlers[:] = []
    logger.addHandler(logging.NullHandler())
    return logger


class SecureSocketTests(unittest.TestCase):
    def test_secure_socket_verifies_certificate_and_sets_sni(self):
        logger = _silent_logger("test_secure_socket_verifies")
        client = SyslogClient(
            "syslog.example.com", "6514", "TCP", logger, secure=True, ca_file="/tmp/ca.pem"
        )
        raw_socket = object()

        with mock.patch("SyslogClient.ssl") as mock_ssl:
            context = mock_ssl.create_default_context.return_value
            wrapped = client.wrap_secure_socket(raw_socket)

        # A default (verifying) context must be used, not the removed ssl.wrap_socket.
        mock_ssl.create_default_context.assert_called_once_with()
        context.load_verify_locations.assert_called_once_with("/tmp/ca.pem")
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="syslog.example.com"
        )
        self.assertIs(wrapped, context.wrap_socket.return_value)

    def test_secure_socket_without_custom_ca_uses_system_trust_store(self):
        logger = _silent_logger("test_secure_socket_system_ca")
        client = SyslogClient("syslog.example.com", "6514", "TCP", logger, secure=True)

        with mock.patch("SyslogClient.ssl") as mock_ssl:
            context = mock_ssl.create_default_context.return_value
            client.wrap_secure_socket(object())

        context.load_verify_locations.assert_not_called()


class UdpDeliveryReportingTests(unittest.TestCase):
    def test_udp_send_returns_none_when_packet_delivery_fails(self):
        logger = _silent_logger("test_udp_failure")
        client = SyslogClient("127.0.0.1", "514", "UDP", logger, payload_format="JSON")

        fake_sock = mock.Mock()
        fake_sock.sendto.side_effect = socket.error("network unreachable")

        with mock.patch("SyslogClient.socket.socket", return_value=fake_sock):
            result = client.send(['{"message":"dropped"}'])

        # A hard socket error must surface as failure so the caller retries.
        self.assertIsNone(result)
        fake_sock.close.assert_called_once()

    def test_udp_send_returns_true_on_success(self):
        logger = _silent_logger("test_udp_success")
        client = SyslogClient("127.0.0.1", "514", "UDP", logger, payload_format="JSON")

        fake_sock = mock.Mock()

        with mock.patch("SyslogClient.socket.socket", return_value=fake_sock):
            result = client.send(['{"message":"delivered"}'])

        self.assertIs(result, True)
        fake_sock.sendto.assert_called_once()
        fake_sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
