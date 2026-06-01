import datetime
import socket
import ssl

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
    def __init__(self, host, port, socket_type, logger, log_hostname="imperva.com", secure=False, payload_format="CEF", tcp_framing="octet", ca_file=None):
        SyslogClient.__init__(self, host, port, socket_type, logger, secure, payload_format, tcp_framing, ca_file)
        self.log_hostname = log_hostname
        self.logger.debug("LEEF syslog enabled. Log Hostname: {}".format(log_hostname))

    def resolve_hostname(self, message):
        if self.log_hostname == "imperva.com":
            return self.get_hostname(message)
        return self.log_hostname

    def send(self, data):
        """
        Send syslog packet to given host and port.
        """
        messages = []
        sock = socket.socket(socket.AF_INET, self.socket_type)
        priority = "<{}>".format(LEVEL['info'] + FACILITY['daemon'] * 8)

        if self.socket_type == socket.SOCK_STREAM:
            for message in data:
                if "|Normal|" in message:
                    continue
                message = self.prepare_message(message)
                hostname = self.resolve_hostname(message)
                msg = self.build_wire_message(message, priority, hostname)
                messages.append(msg)
            if self.secure:
                sock = self.wrap_secure_socket(sock)
                try:
                    sock.connect((self.host, int(self.port)))
                    self.send_tcp_messages(sock, messages)
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
                    if "|Normal|" in message:
                        continue
                    message = self.prepare_message(message)
                    hostname = self.resolve_hostname(message)
                    msg = "{}\n".format(self.build_wire_message(message, priority, hostname))
                    try:
                        sock.sendto(bytes(msg, 'utf-8'), (self.host, int(self.port)))
                    except socket.error as e:
                        self.logger.error(e)
                        success = False
            finally:
                sock.close()
            return True if success else None

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
