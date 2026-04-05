import json
import time

from LeefFormatter import LeefFormatter


class CefFormatter:
    def __init__(self, logger, vendor="Imperva", product="CloudWAF", version="1.0"):
        self.logger = logger
        self.vendor = vendor
        self.product = product
        self.version = version
        self.leef_formatter = LeefFormatter(logger, vendor, product, version)

    def format(self, message):
        message = (message or "").rstrip("\r\n")
        if not message:
            return ""
        if message.startswith("CEF:"):
            return message
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return self._format_raw(message)
        return self._format_json(payload, message)

    def _format_json(self, payload, raw_message):
        fields = {}
        self.leef_formatter._flatten(payload, fields)

        signature_id = (
            fields.get("imperva_audit_trail_event_action")
            or fields.get("event_dataset")
            or fields.get("event_provider")
            or "imperva_event"
        )
        name = fields.get("message") or signature_id
        severity = fields.get("event_severity") or "5"

        event_time = fields.get("_timestamp") or fields.get("timestamp") or str(int(time.time() * 1000))
        fields["start"] = str(event_time)
        fields.setdefault("sourceServiceName",
                          fields.get("imperva_audit_trail_resource_name")
                          or fields.get("imperva_ids_site_id")
                          or fields.get("imperva_ids_account_name")
                          or "imperva.com")
        fields["rawPayload"] = raw_message

        return self._build_cef(signature_id, name, severity, fields)

    def _format_raw(self, message):
        timestamp = str(int(time.time() * 1000))
        fields = {
            "msg": message,
            "start": timestamp,
            "sourceServiceName": "imperva.com",
        }
        return self._build_cef("raw_event", "raw_event", "5", fields)

    def _build_cef(self, signature_id, name, severity, fields):
        extension = []
        for key in sorted(fields):
            value = fields[key]
            if value is None:
                continue
            extension.append("{}={}".format(key, self._escape_value(str(value))))
        return "CEF:0|{}|{}|{}|{}|{}|{}|{}".format(
            self._escape_header(self.vendor),
            self._escape_header(self.product),
            self._escape_header(self.version),
            self._escape_header(signature_id),
            self._escape_header(name),
            self._escape_header(str(severity)),
            " ".join(extension)
        )

    @staticmethod
    def _escape_header(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _escape_value(value):
        return (
            value.replace("\\", "\\\\")
            .replace("=", r"\=")
            .replace("|", r"\|")
            .replace("\n", r"\n")
            .replace("\r", r"\r")
        )
