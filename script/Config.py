import configparser
import os

"""

Config - A class for reading the configuration file

"""

class Config:

    def __init__(self, config_path, logger):
        self.config_path = config_path
        self.logger = logger

    """
    Reads the configuration file
    """

    def read(self):
        config_file = os.path.join(self.config_path, "Settings.Config")
        if os.path.exists(config_file):
            config_parser = configparser.ConfigParser()
            config_parser.read(config_file)
            config = Config(self.config_path, self.logger)

            _UNSET = object()

            def resolve(env_name, section_key, fallback=_UNSET):
                """Environment variable wins; only fall back to the config file when the
                env var is unset. The config lookup is lazy so an env-only deployment does
                not crash when an optional key is missing from Settings.Config."""
                env_value = os.environ.get(env_name)
                if env_value is not None:
                    return env_value
                if fallback is _UNSET:
                    return config_parser.get("SETTINGS", section_key)
                return config_parser.get("SETTINGS", section_key, fallback=fallback)

            # Check for environment variables first, then load config values.
            # Backwards compatibility with non-docker deployments
            config.API_ID = resolve('IMPERVA_API_ID', "IMPERVA_API_ID")
            config.API_KEY = resolve('IMPERVA_API_KEY', "IMPERVA_API_KEY")
            config.INCOMING_DIR = os.environ.get('IMPERVA_INCOMING_DIR',
                                                 os.path.join(config_parser.get('SETTINGS', 'IMPERVA_INCOMING_DIR'), "")
                                                 or os.path.join(os.getcwd(), "incoming"))
            config.PROCESS_DIR = os.environ.get('IMPERVA_PROCESS_DIR',
                                                os.path.join(config_parser.get("SETTINGS", "IMPERVA_PROCESS_DIR"), "")
                                                or os.path.join(os.getcwd(), "process"))
            archive_dir = resolve('IMPERVA_ARCHIVE_DIR', 'IMPERVA_ARCHIVE_DIR', fallback="")
            config.ARCHIVE_DIR = os.path.join(archive_dir, "") if archive_dir else False
            config.BASE_URL = resolve('IMPERVA_API_URL', "IMPERVA_API_URL")
            config.USE_PROXY = resolve('IMPERVA_USE_PROXY', "IMPERVA_USE_PROXY", fallback="NO")
            config.PROXY_SERVER = resolve('IMPERVA_PROXY_SERVER', "IMPERVA_PROXY_SERVER", fallback="NO")
            config.USE_CUSTOM_CA_FILE = resolve('IMPERVA_USE_CUSTOM_CA_FILE', 'IMPERVA_USE_CUSTOM_CA_FILE', fallback="NO")
            config.CUSTOM_CA_FILE = resolve('IMPERVA_CUSTOM_CA_FILE', 'IMPERVA_CUSTOM_CA_FILE', fallback="")
            config.SYSLOG_ENABLE = resolve('IMPERVA_SYSLOG_ENABLE', 'IMPERVA_SYSLOG_ENABLE', fallback="NO")
            config.IMPERVA_SYSLOG_SECURE = resolve('IMPERVA_SYSLOG_SECURE', 'IMPERVA_SYSLOG_SECURE', fallback="NO")
            config.SYSLOG_ADDRESS = resolve('IMPERVA_SYSLOG_ADDRESS', 'IMPERVA_SYSLOG_ADDRESS', fallback="")
            config.SYSLOG_PORT = resolve('IMPERVA_SYSLOG_PORT', 'IMPERVA_SYSLOG_PORT', fallback="")
            config.SYSLOG_PROTO = resolve('IMPERVA_SYSLOG_PROTO', 'IMPERVA_SYSLOG_PROTO', fallback="UDP")
            config.SYSLOG_TCP_FRAMING = os.environ.get(
                'SYSLOG_TCP_FRAMING',
                os.environ.get(
                    'IMPERVA_SYSLOG_TCP_FRAMING',
                    config_parser.get('SETTINGS', 'SYSLOG_TCP_FRAMING', fallback="octet")
                )
            ).lower()
            config.SYSLOG_CUSTOM = resolve('IMPERVA_SYSLOG_CUSTOM', 'IMPERVA_SYSLOG_CUSTOM', fallback="NO")
            config.SYSLOG_FORMAT = resolve('IMPERVA_SYSLOG_FORMAT', 'IMPERVA_SYSLOG_FORMAT', fallback="LEEF").upper()
            config.SYSLOG_SENDER_HOSTNAME = resolve('IMPERVA_SYSLOG_SENDER_HOSTNAME', 'IMPERVA_SYSLOG_SENDER_HOSTNAME', fallback="imperva.com")
            config.SPLUNK_HEC = resolve('IMPERVA_SPLUNK_HEC', 'IMPERVA_SPLUNK_HEC', fallback="NO")
            config.SPLUNK_HEC_IP = resolve('IMPERVA_SPLUNK_HEC_IP', 'IMPERVA_SPLUNK_HEC_IP', fallback="")
            config.SPLUNK_HEC_PORT = resolve('IMPERVA_SPLUNK_HEC_PORT', 'IMPERVA_SPLUNK_HEC_PORT', fallback="")
            config.SPLUNK_HEC_TOKEN = resolve('IMPERVA_SPLUNK_HEC_TOKEN', 'IMPERVA_SPLUNK_HEC_TOKEN', fallback="")
            config.SPLUNK_HEC_SRC_HOSTNAME = resolve('IMPERVA_SPLUNK_HEC_SRC_HOSTNAME', 'IMPERVA_SPLUNK_HEC_SRC_HOSTNAME', fallback="")
            config.SPLUNK_HEC_INDEX = resolve('IMPERVA_SPLUNK_HEC_INDEX', 'IMPERVA_SPLUNK_HEC_INDEX', fallback="imperva")
            config.SPLUNK_HEC_SOURCE = resolve('IMPERVA_SPLUNK_HEC_SOURCE', 'IMPERVA_SPLUNK_HEC_SOURCE', fallback="log_downloader")
            config.SPLUNK_HEC_SOURCETYPE = resolve('IMPERVA_SPLUNK_HEC_SOURCETYPE', 'IMPERVA_SPLUNK_HEC_SOURCETYPE', fallback="imperva:cef")
            return config
        else:
            self.logger.error("Could Not find configuration file %s", config_file)
            raise Exception("Could Not find configuration file")
