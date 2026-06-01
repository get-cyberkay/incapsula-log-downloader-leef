import json
import re
import time


class LeefFormatter:
    HEADER_DELIMITER = "\t"
    KEY_SANITIZER = re.compile(r"[^A-Za-z0-9_]")

    def __init__(self, logger, vendor="Imperva", product="CloudWAF", version="1.0"):
        self.logger = logger
        self.vendor = vendor
        self.product = product
        self.version = version

    def format(self, message):
        message = (message or "").rstrip("\r\n")
        if not message:
            return ""
        if message.startswith("LEEF:"):
            return message
        if message.startswith("CEF:"):
            return self._format_cef(message)
        return self._format_json_or_raw(message)

    def _format_cef(self, message):
        header_fields, extension = self._split_cef(message)
        if len(header_fields) < 7:
            return self._format_raw(message, "cef_parse_error")

        _, device_vendor, device_product, device_version, signature_id, name, severity = header_fields[:7]
        fields = self._parse_cef_extension(extension)
        fields["cefVersion"] = "0"
        fields["eventName"] = name
        fields["severity"] = severity
        fields.setdefault("devTimeFormat", "epochms")
        if "start" not in fields:
            fields["start"] = str(int(time.time() * 1000))
        fields.setdefault("devTime", fields.get("end") or fields.get("start"))
        fields.setdefault("sourceServiceName", fields.get("sourceServiceName") or device_product or self.product)

        return self._build_leef(
            device_vendor or self.vendor,
            device_product or self.product,
            device_version or self.version,
            signature_id or name or "imperva_event",
            fields
        )

    def _format_json_or_raw(self, message):
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return self._format_raw(message)

        fields = {}
        self._flatten(payload, fields)

        event_id = (
            fields.get("imperva_audit_trail_event_action")
            or fields.get("event_dataset")
            or fields.get("event_provider")
            or fields.get("message")
            or "imperva_event"
        )

        source_service_name = (
            fields.get("imperva_audit_trail_resource_name")
            or fields.get("imperva_ids_site_id")
            or fields.get("imperva_ids_account_name")
            or fields.get("host_name")
            or "imperva.com"
        )

        event_time = fields.get("_timestamp") or fields.get("timestamp")
        if event_time is not None:
            fields["start"] = str(event_time)
            fields.setdefault("devTimeFormat", "epochms")
        else:
            fields["start"] = str(int(time.time() * 1000))
            fields.setdefault("devTimeFormat", "epochms")
        fields["devTime"] = fields["start"]

        fields["sourceServiceName"] = source_service_name
        fields["rawPayload"] = message

        return self._build_leef(self.vendor, self.product, self.version, event_id, fields)

    def _format_raw(self, message, event_id="raw_event"):
        timestamp = str(int(time.time() * 1000))
        fields = {
            "message": message,
            "start": timestamp,
            "devTime": timestamp,
            "devTimeFormat": "epochms",
            "sourceServiceName": "imperva.com"
        }
        return self._build_leef(self.vendor, self.product, self.version, event_id, fields)

    def _build_leef(self, vendor, product, version, event_id, fields):
        encoded_fields = []
        for key in sorted(fields):
            if fields[key] is None:
                continue
            safe_key = self._sanitize_key(key)
            encoded_fields.append("{}={}".format(safe_key, self._escape_value(fields[key])))
        return "LEEF:2.0|{}|{}|{}|{}|{}".format(
            self._escape_header(vendor),
            self._escape_header(product),
            self._escape_header(version),
            self._escape_header(event_id),
            self.HEADER_DELIMITER.join(encoded_fields)
        )

    def _flatten(self, value, result, prefix=""):
        if isinstance(value, dict):
            for key, nested_value in value.items():
                next_prefix = self._join_key(prefix, key)
                self._flatten(nested_value, result, next_prefix)
        elif isinstance(value, list):
            if not value:
                result[self._sanitize_key(prefix)] = "[]"
            for index, nested_value in enumerate(value):
                next_prefix = self._join_key(prefix, index)
                self._flatten(nested_value, result, next_prefix)
        else:
            result[self._sanitize_key(prefix)] = self._stringify(value)

    def _split_cef(self, message):
        parts = []
        current = []
        escaped = False
        for char in message:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                continue
            if char == "|" and len(parts) < 7:
                parts.append("".join(current))
                current = []
                continue
            current.append(char)
        parts.append("".join(current))
        header = parts[:7]
        extension = parts[7] if len(parts) > 7 else ""
        return header, extension

    def _parse_cef_extension(self, extension):
        if not extension:
            return {}
        matches = list(re.finditer(r"(?:^| )([A-Za-z0-9_.-]+)=", extension))
        if not matches:
            return {"message": extension}

        fields = {}
        for index, match in enumerate(matches):
            key = match.group(1)
            value_start = match.end()
            value_end = matches[index + 1].start() if index + 1 < len(matches) else len(extension)
            value = extension[value_start:value_end].rstrip()
            fields[key] = self._unescape_cef_value(value)
        return fields

    def _sanitize_key(self, key):
        sanitized = self.KEY_SANITIZER.sub("_", str(key or "field")).strip("_")
        if not sanitized:
            sanitized = "field"
        if sanitized[0].isdigit():
            sanitized = "field_{}".format(sanitized)
        return sanitized

    def _escape_value(self, value):
        return self._stringify(value).replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")

    def _escape_header(self, value):
        return self._stringify(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _stringify(value):
        if isinstance(value, bool):
            return str(value).lower()
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _unescape_cef_value(value):
        return (
            value.replace(r"\=", "=")
            .replace(r"\|", "|")
            .replace(r"\\", "\\")
            .replace(r"\n", "\n")
            .replace(r"\r", "\r")
        )

    @staticmethod
    def _join_key(prefix, key):
        if prefix:
            return "{}_{}".format(prefix, key)
        return str(key)
