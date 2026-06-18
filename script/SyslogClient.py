import datetime
import json
import socket
import ssl
from CefFormatter import CefFormatter
from LeefFormatter import LeefFormatter

FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

"""

Syslog - For sending TCP Syslog messages via socket class

"""


# Create a raw socket client to send messages to syslog server
class SyslogClient:
    MAX_UDP_PAYLOAD_BYTES = 65000

    def __init__(self, host, port, socket_type, logger, secure=False, payload_format="CEF", tcp_framing="octet", ca_file=None,
                 log_hostname="imperva.com", leef_version="1.0", leef_syslog_header=True, syslog_facility="local0"):
        self.host = host
        self.port = port
        self.socket_type = socket.SOCK_STREAM if socket_type == "TCP" else socket.SOCK_DGRAM
        self.logger = logger
        self.logger.debug("Send to Host={} on Port={}".format(self.host, self.port))
        self.secure = secure
        self.ca_file = ca_file or None
        self.payload_format = (payload_format or "CEF").upper()
        self.tcp_framing = (tcp_framing or "octet").lower()
        if self.tcp_framing not in ("octet", "newline"):
            self.logger.warning(
                "Unsupported SYSLOG_TCP_FRAMING value '%s'. Falling back to RFC6587 octet framing.",
                self.tcp_framing
            )
            self.tcp_framing = "octet"
        # Hostname placed in the syslog header. An operator-supplied value (anything other
        # than the "imperva.com" default) is used verbatim; the default falls back to a
        # hostname derived from the message payload.
        self.log_hostname = log_hostname or "imperva.com"
        # When True, LEEF records are wrapped in a full RFC3164 syslog header
        # (<pri> timestamp hostname app LEEF:...). When False, the bare LEEF record is sent.
        self.leef_syslog_header = leef_syslog_header
        # Syslog facility used to compute the RFC3164 PRI (facility * 8 + severity).
        # Severity is fixed at "info" (6); facility defaults to local0 (16) -> PRI 134.
        self.facility = self.resolve_facility(syslog_facility)
        self.leef_formatter = LeefFormatter(self.logger, leef_version=leef_version)
        self.cef_formatter = CefFormatter(self.logger)

    def resolve_facility(self, facility):
        """Resolve a syslog facility supplied as a name (e.g. 'local0', 'daemon') or a
        numeric code (0-23) into its integer code. Falls back to local0 when unset or
        unrecognised."""
        if facility is None or facility == "":
            return FACILITY['local0']
        if isinstance(facility, int):
            return facility
        facility = str(facility).strip().lower()
        if facility.isdigit():
            return int(facility)
        if facility in FACILITY:
            return FACILITY[facility]
        self.logger.warning(
            "Unknown SYSLOG_FACILITY value '%s'. Falling back to local0.", facility
        )
        return FACILITY['local0']

    def get_priority(self):
        """RFC3164 PRI value: facility * 8 + severity (severity fixed at info=6)."""
        return "<{}>".format(LEVEL['info'] + self.facility * 8)

    def wrap_secure_socket(self, sock):
        """Wrap a TCP socket in a TLS context that verifies the server certificate.

        Uses the system trust store by default; a custom CA bundle is honoured when
        configured. server_hostname is set so SNI and hostname verification work.
        """
        context = ssl.create_default_context()
        if self.ca_file:
            context.load_verify_locations(self.ca_file)
        return context.wrap_socket(sock, server_hostname=self.host)

    def frame_tcp_message(self, message):
        message = (message or "").rstrip("\r\n")
        if self.tcp_framing == "newline":
            return "{}\n".format(message).encode('utf-8')
        payload = message.encode('utf-8')
        return "{} ".format(len(payload)).encode('ascii') + payload

    def send_tcp_messages(self, sock, messages):
        for message in messages:
            sock.sendall(self.frame_tcp_message(message))

    def should_send_payload_only(self, message):
        return (
            self.payload_format == "LEEF"
            and message.startswith("LEEF:")
            and not self.leef_syslog_header
        )

    def resolve_hostname(self, message):
        """Use the operator-configured hostname when one is set, otherwise derive it
        from the message payload (sourceServiceName / host fields)."""
        if not self.log_hostname or self.log_hostname == "imperva.com":
            return self.get_hostname(message)
        return self.log_hostname

    def build_wire_message(self, message, priority, hostname=None):
        if self.should_send_payload_only(message):
            return message
        timestamp = self.get_time(message)
        hostname = hostname or self.resolve_hostname(message)
        # RFC3164 header without an APP-NAME/tag token: the hostname is the only
        # field the SIEM uses as the Log Source Identifier.
        return "{} {} {} {}".format(priority, timestamp, hostname, message)

    # Send the messages
    def send(self, data):
        """
        Send syslog packet to given host and port.
        """
        messages = []
        sock = socket.socket(socket.AF_INET, self.socket_type)
        priority = self.get_priority()

        if self.socket_type == socket.SOCK_STREAM:
            # Loop over the data/messages array and create the relevant object(s) to be sent.
            for message in data:
                message = self.prepare_message(message)
                msg = self.build_wire_message(message, priority)
                messages.append(msg)
            if self.secure:
                sock = self.wrap_secure_socket(sock)
                try:
                    sock.connect((self.host, int(self.port)))
                    self.send_tcp_messages(sock, messages)
                    # Returning true if everything is good, if not log the error and return None.
                    return True
                except (ssl.SSLError, socket.error) as e:
                    self.logger.error(e)
                    return None
                finally:
                    sock.close()
            else:
                try:
                    sock.connect((self.host, int(self.port)))
                    self.send_tcp_messages(sock, messages)
                    # Returning true if everything is good, if not log the error and return None.
                    return True
                except socket.error as e:
                    self.logger.error(e)
                    return None
                finally:
                    sock.close()
        elif self.socket_type == socket.SOCK_DGRAM:
            success = True
            try:
                for message in data:
                    message = self.prepare_message(message)
                    msg = "{}\n".format(self.build_wire_message(message, priority))
                    try:
                        payload = msg.encode('utf-8')
                        if len(payload) > self.MAX_UDP_PAYLOAD_BYTES:
                            self.logger.warning(
                                "UDP syslog payload is %s bytes and may be truncated or dropped. Use TCP/TLS to avoid truncation.",
                                len(payload)
                            )
                        sock.sendto(payload, (self.host, int(self.port)))
                    except socket.error as e:
                        # A hard socket error (unreachable host, bad port) is reportable;
                        # flag the batch as failed so the caller retries instead of
                        # silently dropping the logs.
                        self.logger.error(e)
                        success = False
            finally:
                sock.close()
            return True if success else None

    def prepare_message(self, message):
        message = (message or "").rstrip("\r\n")
        if self.payload_format == "LEEF":
            return self.leef_formatter.format(message)
        if self.payload_format == "CEF":
            return self.cef_formatter.format(message)
        if self.payload_format == "JSON":
            return self.format_json(message)
        return message

    def format_json(self, message):
        message = (message or "").rstrip("\r\n")
        if not message:
            return ""
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            if message.startswith("CEF:"):
                header_fields, extension = self.leef_formatter._split_cef(message)
                cef_payload = {
                    "format": "CEF",
                    "cef_version": header_fields[0].split(":", 1)[1] if header_fields and header_fields[0].startswith("CEF:") else "0",
                    "device_vendor": header_fields[1] if len(header_fields) > 1 else "",
                    "device_product": header_fields[2] if len(header_fields) > 2 else "",
                    "device_version": header_fields[3] if len(header_fields) > 3 else "",
                    "signature_id": header_fields[4] if len(header_fields) > 4 else "",
                    "name": header_fields[5] if len(header_fields) > 5 else "",
                    "severity": header_fields[6] if len(header_fields) > 6 else "",
                    "extensions": self.leef_formatter._parse_cef_extension(extension)
                }
                return json.dumps(cef_payload, separators=(",", ":"), ensure_ascii=True)
            return json.dumps({"message": message}, separators=(",", ":"), ensure_ascii=True)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)

    # Function used to get the inbound timestamp to set the indexed time in epoch
    def get_time(self, message):
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        try:
            if message.startswith("CEF"):
                epoch = int(str(message.split("start=")[1]).split(" ")[0]) / 1000
                timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                            datetime.datetime.now().strftime("%b %d %H:%M:%S")
            elif message.startswith("LEEF"):
                epoch = int(str(message.split("start=")[1]).split("\t")[0]) / 1000
                timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                            datetime.datetime.now().strftime("%b %d %H:%M:%S")
            elif message.startswith("{"):
                payload = json.loads(message)
                epoch = int(payload.get("@timestamp") or payload.get("timestamp")) / 1000
                timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                            datetime.datetime.now().strftime("%b %d %H:%M:%S")
        except (IndexError, ValueError, TypeError, json.JSONDecodeError):
            self.logger.error("Error converting epoch time.")
        return timestamp

    # Function used to get the host name from the inbound hostname/service name
    def get_hostname(self, message):
        hostname = "imperva.com"
        try:
            if message.startswith("CEF"):
                hostname = str(message.split("sourceServiceName=")[1]).split(" ")[0] or "imperva.com"
            elif message.startswith("LEEF"):
                hostname = str(message.split("sourceServiceName=")[1]).split("\t")[0] or "imperva.com"
            elif message.startswith("{"):
                payload = json.loads(message)
                hostname = (
                    payload.get("host", {}).get("name")
                    or payload.get("user", {}).get("email")
                    or payload.get("imperva", {}).get("audit_trail", {}).get("resource_name")
                    or "imperva.com"
                )
        except (IndexError, json.JSONDecodeError, AttributeError):
            self.logger.error("Error getting hostname.")
        return hostname
