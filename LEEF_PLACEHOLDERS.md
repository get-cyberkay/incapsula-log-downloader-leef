# LEEF Placeholders

Every placeholder (field key) that `LeefFormatter` emits in a `LEEF:1.0` record,
with its description.

## Header

The record banner is `LEEF:<leef_version>|Vendor|Product|Version|eventID|attributes`,
where `<leef_version>` is `1.0` by default (configurable via `IMPERVA_LEEF_VERSION`).
When delivered over syslog the record is, by default, prefixed with an RFC3164 header
(`<pri> timestamp hostname cwaf LEEF:...`); the hostname comes from
`IMPERVA_SYSLOG_SENDER_HOSTNAME` and the header can be disabled with
`IMPERVA_LEEF_SYSLOG_HEADER=NO`.

| Placeholder | Description                                                     |
| ----------- | --------------------------------------------------------------- |
| Vendor      | Device vendor (`Imperva` by default).                           |
| Product     | Device product (`CloudWAF` by default).                         |
| Version     | Device version (`1.0` by default).                              |
| eventID     | Event type identifier (CEF Signature ID or audit event action). |

## Synthetic

| Placeholder       | Description                                          |
| ----------------- | ---------------------------------------------------- |
| cefVersion        | Records that the LEEF was transcoded from CEF v0.    |
| eventName         | Human-readable event title.                          |
| severity          | Event severity value.                                |
| start             | Event start time (epoch ms).                         |
| devTime           | Device event time (epoch ms).                        |
| devTimeFormat     | Time format hint; always `epochms`.                  |
| sourceServiceName | Originating service/host.                            |
| rawPayload        | The complete original JSON line, preserved verbatim. |
| message           | The original line (raw fallback only).               |

## Traffic events

| Placeholder              | Description                                             |
| ------------------------ | ------------------------------------------------------- |
| act                      | Action Imperva took on the request (e.g.`REQ_PASSED`).  |
| app                      | Application protocol (e.g.`HTTPS`).                     |
| Customer                 | Account / customer display name.                        |
| ccode                    | Visitor country code (ISO).                             |
| cicode                   | Visitor city code/name.                                 |
| cn1                      | HTTP response status code returned to the client.       |
| cpt                      | Client (source) TCP port.                               |
| deviceExternalId         | Unique Imperva request/visit identifier.                |
| deviceFacility           | Imperva PoP / data-center code that served the request. |
| dproc                    | Device process / client type (e.g.`Browser`).           |
| end                      | Request end time (epoch ms).                            |
| fileId                   | Source log-file record id.                              |
| filePermission           | Internal file permission flag.                          |
| fileType                 | Internal file/content type id.                          |
| in                       | Bytes received from the client (request size).          |
| postbody                 | Captured HTTP POST body.                                |
| qstr                     | Request query string.                                   |
| ref                      | HTTP Referer header.                                    |
| request                  | Full requested URL (host + path).                       |
| requestClientApplication | User-Agent string.                                      |
| requestMethod            | HTTP method.                                            |
| sip                      | Server / origin IP address.                             |
| siteid                   | Imperva site (website) id.                              |
| spt                      | Server (destination) port.                              |
| src                      | Client (source) IP address.                             |
| suid                     | Subscriber / account id.                                |
| ver                      | TLS version and negotiated cipher suite.                |
| xff                      | `X-Forwarded-For` header value.                         |
| cs1 / cs1Label           | Cap Support.                                            |
| cs2 / cs2Label           | Javascript Support.                                     |
| cs3 / cs3Label           | CO (cookie) Support.                                    |
| cs4 / cs4Label           | VID (visitor id).                                       |
| cs5 / cs5Label           | clappsig (client-app signature).                        |
| cs6 / cs6Label           | clapp (client application).                             |
| cs7 / cs7Label           | Latitude.                                               |
| cs8 / cs8Label           | Longitude.                                              |
| cs9 / cs9Label           | Rule name.                                              |
| cs11 / cs11Label         | Rule Additional Info.                                   |

## Audit-trail events

| Placeholder                                   | Description                                |
| --------------------------------------------- | ------------------------------------------ |
| event_provider                                | Event source category (e.g.`audit`).       |
| event_dataset                                 | Dataset name (e.g.`AUDIT_TRAIL`).          |
| imperva_ids_account_id                        | Account id.                                |
| imperva_ids_account_name                      | Account name.                              |
| imperva_ids_site_id                           | Affected site id.                          |
| imperva_ids_site_name                         | Affected site name.                        |
| imperva_audit_trail_event_action              | Audit action code.                         |
| imperva_audit_trail_event_action_description  | Human-readable action.                     |
| imperva_audit_trail_event_context             | Action context code (where it originated). |
| imperva_audit_trail_event_context_description | Human-readable context.                    |
| imperva_audit_trail_resource_name             | Resource the action targeted.              |
| imperva_audit_trail_resource_type             | Resource type code.                        |
| imperva_audit_trail_resource_type_description | Human-readable resource type.              |
| user_email                                    | Actor who triggered the event.             |
| message                                       | Event summary text.                        |
| timestamp                                     | Event timestamp (epoch ms).                |

## Account-notification events

| Placeholder                 | Description                                |
| --------------------------- | ------------------------------------------ |
| imperva_alert_type          | Alert classification (e.g.`NEVER_ACTIVE`). |
| imperva_message             | Alert message text.                        |
| imperva_endpoint_id         | Affected endpoint id.                      |
| imperva_baseline_window     | Baseline comparison window.                |
| imperva_comparison_window   | Current comparison window.                 |
| imperva_total_requests      | Total requests in window.                  |
| imperva_successful_requests | Successful requests in window.             |
| imperva_failed_requests     | Failed requests in window.                 |
| imperva_blocked_requests    | Blocked requests in window.                |
