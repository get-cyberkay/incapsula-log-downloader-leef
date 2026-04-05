import datetime
import socket
import ssl
from collections import OrderedDict

from SyslogClient import SyslogClient


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
Syslog - For sending TCP/UDP Syslog messages with QRadar-friendly LEEF payloads.
"""


class SyslogClientCustom(SyslogClient):
    LEEF_VERSION = "2.0"
    DEFAULT_VENDOR = "Imperva"
    DEFAULT_PRODUCT = "Incapsula"

    def __init__(self, host, port, socket_type, logger, log_hostname="imperva.com", secure=False, payload_format="CEF"):
        SyslogClient.__init__(self, host, port, socket_type, logger, secure, payload_format)
        self.log_hostname = log_hostname
        self.logger.debug("LEEF syslog enabled. Log Hostname: {}".format(log_hostname))

    def _split_escaped(self, text, delimiter, maxsplit=-1):
        parts = []
        current = []
        escaped = False
        splits = 0

        for char in text:
            if escaped:
                current.append("\\")
                current.append(char)
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if char == delimiter and (maxsplit < 0 or splits < maxsplit):
                parts.append("".join(current))
                current = []
                splits += 1
                continue

            current.append(char)

        if escaped:
            current.append("\\")

        parts.append("".join(current))
        return parts

    def _unescape_cef_value(self, value):
        unescaped = []
        escaped = False
        translations = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }

        for char in value:
            if escaped:
                unescaped.append(translations.get(char, char))
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            unescaped.append(char)

        if escaped:
            unescaped.append("\\")

        return "".join(unescaped)

    def _escape_leef_value(self, value):
        return (
            value.replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
        )

    def _parse_cef_extension(self, extension):
        parsed = OrderedDict()
        for token in self._split_escaped(extension.strip(), " "):
            if not token:
                continue
            key_value = self._split_escaped(token, "=", 1)
            if len(key_value) != 2:
                parsed[token] = ""
                continue
            key = self._unescape_cef_value(key_value[0].strip())
            value = self._unescape_cef_value(key_value[1].strip())
            if key:
                parsed[key] = value
        return parsed

    def _parse_cef_message(self, message):
        if not message.startswith("CEF:"):
            return None

        header_parts = self._split_escaped(message[4:], "|", 7)
        if len(header_parts) < 8:
            return None

        cef_version = self._unescape_cef_value(header_parts[0].strip())
        vendor = self._unescape_cef_value(header_parts[1].strip()) or self.DEFAULT_VENDOR
        product = self._unescape_cef_value(header_parts[2].strip()) or self.DEFAULT_PRODUCT
        device_version = self._unescape_cef_value(header_parts[3].strip())
        signature_id = self._unescape_cef_value(header_parts[4].strip())
        name = self._unescape_cef_value(header_parts[5].strip())
        severity = self._unescape_cef_value(header_parts[6].strip())
        extension = header_parts[7]
        extension_fields = self._parse_cef_extension(extension)

        return {
            "cef_version": cef_version,
            "vendor": vendor,
            "product": product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
            "extension_fields": extension_fields,
        }

    def _coerce_leef_event_id(self, cef):
        extension_fields = cef["extension_fields"]
        if extension_fields.get("deviceExternalId"):
            return extension_fields["deviceExternalId"]
        if cef["signature_id"]:
            return cef["signature_id"]
        if cef["name"]:
            return cef["name"]
        return "0"

    def _build_leef_message(self, message):
        cef = self._parse_cef_message(message)
        if cef is None:
            return message

        leef_fields = OrderedDict()
        leef_fields["eventName"] = cef["name"]
        leef_fields["severity"] = cef["severity"]
        for key, value in cef["extension_fields"].items():
            leef_fields[key] = value

        # Preserve the original event timestamp in a QRadar-friendly field when we have it.
        if "devTime" not in leef_fields:
            timestamp_field = leef_fields.get("end") or leef_fields.get("start")
            if timestamp_field:
                try:
                    epoch_seconds = int(timestamp_field) / 1000
                    leef_fields["devTime"] = datetime.datetime.fromtimestamp(
                        epoch_seconds, datetime.timezone.utc
                    ).isoformat().replace("+00:00", "Z")
                except (TypeError, ValueError, OSError):
                    pass

        header = [
            "LEEF:{}".format(self.LEEF_VERSION),
            cef["vendor"],
            cef["product"],
            cef["device_version"] or cef["cef_version"] or "1.0",
            self._coerce_leef_event_id(cef),
        ]

        extensions = []
        for key, value in leef_fields.items():
            if value == "":
                extensions.append(key)
            else:
                extensions.append("{}={}".format(key, self._escape_leef_value(value)))

        payload = "|".join(header) + "|"
        if extensions:
            payload += "\t".join(extensions)
        return payload

    def message_customize(self, msg):
        if msg == "":
            return msg
        if msg.startswith("LEEF:"):
            return msg
        if self.payload_format == "LEEF":
            return self.prepare_message(msg)
        return msg

    def send(self, data):
        """
        Send syslog packet to given host and port.
        """
        messages = ""
        sock = socket.socket(socket.AF_INET, self.socket_type)
        priority = "<{}>".format(LEVEL['info'] + FACILITY['daemon'] * 8)

        if self.socket_type == socket.SOCK_STREAM:
            for message in data:
                if "|Normal|" in message:
                    continue
                message = self.prepare_message(message)
                if self.log_hostname == "imperva.com":
                    hostname = self.get_hostname(message)
                else:
                    hostname = self.log_hostname
                timestamp = self.get_time(message)
                application = "cwaf"
                customized_message = self.message_customize(message)
                msg = "{} {} {} {} {}\n".format(priority, timestamp, hostname, application, customized_message)
                messages += msg
            if self.secure:
                sock = ssl.wrap_socket(sock)
                try:
                    sock.connect((self.host, int(self.port)))
                    sock.send(bytes(messages, 'utf-8'))
                    return True
                except ssl.SSLError as e:
                    self.logger.error(e)
                    return None
                finally:
                    sock.close()
            else:
                try:
                    sock.connect((self.host, int(self.port)))
                    sock.send(bytes(messages, 'utf-8'))
                    return True
                except socket.error as e:
                    self.logger.error(e)
                    return None
                finally:
                    sock.close()
        elif self.socket_type == socket.SOCK_DGRAM:
            for message in data:
                if "|Normal|" in message:
                    continue
                message = self.prepare_message(message)
                if self.log_hostname == "imperva.com":
                    hostname = self.get_hostname(message)
                else:
                    hostname = self.log_hostname
                timestamp = self.get_time(message)
                application = "cwaf"
                customized_message = self.message_customize(message)
                msg = "{} {} {} {} {}\n".format(priority, timestamp, hostname, application, customized_message)
                try:
                    sock.sendto(bytes(msg, 'utf-8'), (self.host, int(self.port)))
                except socket.error as e:
                    self.logger.error(e)
            return True

    def get_time(self, message):
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        try:
            if message.startswith("CEF"):
                epoch = int(str(message.split("end=")[1]).split(" ")[0]) / 1000
                timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                            datetime.datetime.now().strftime("%b %d %H:%M:%S")
            elif message.startswith("LEEF"):
                epoch = int(str(message.split("end=")[1]).split("\t")[0]) / 1000
                timestamp = datetime.datetime.fromtimestamp(int(epoch)).strftime("%b %d %H:%M:%S") or \
                            datetime.datetime.now().strftime("%b %d %H:%M:%S")
            elif message.startswith("{"):
                return SyslogClient.get_time(self, message)
        except (IndexError, ValueError, TypeError, OSError):
            self.logger.error("Error converting epoch time.")
        return timestamp

    def get_hostname(self, message):
        hostname = "imperva.com"
        try:
            if message.startswith("CEF"):
                hostname = str(message.split("sourceServiceName=")[1]).split(" ")[0] or "imperva.com"
            elif message.startswith("LEEF"):
                hostname = str(message.split("sourceServiceName=")[1]).split("\t")[0] or "imperva.com"
            elif message.startswith("{"):
                return SyslogClient.get_hostname(self, message)
        except IndexError:
            self.logger.error("Error getting hostname.")
        return hostname
