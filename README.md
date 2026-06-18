# Incapsula Log Downloader LEEF

> A public fork of Imperva's log downloader with configurable `LEEF`, `CEF`, and `JSON` syslog output.

This fork is intended for teams that want to keep Imperva log collection behavior while adding SIEM-friendly output control for QRadar, CEF consumers, and JSON pipelines.

## Acknowledgment

This project is based on Imperva's original `incapsula-logs-downloader` repository and keeps that work as the foundation for log retrieval, decryption, file handling, and syslog delivery.

Original project:
- https://github.com/imperva/incapsula-logs-downloader

## Improvements In This Fork

- Added configurable outbound syslog payload formats: `LEEF`, `CEF`, and `JSON`
- Added QRadar-friendly LEEF output generation (configurable `LEEF:1.0`/`LEEF:2.0`, default `1.0`) for both CEF input and live JSON log input, with a configurable syslog-header hostname
- Added JSON-to-CEF conversion so current Imperva JSON events can still be sent to CEF-based consumers
- Added raw JSON ingestion for single JSON objects, JSON arrays, common event-list envelopes, and newline-delimited JSON
- Added config-driven payload selection with `IMPERVA_SYSLOG_FORMAT`
- Improved large-event handling by using TCP `sendall()` for full writes
- Added explicit warning when oversized UDP syslog payloads may be truncated or dropped
- Preserved source event fidelity with full-field flattening and optional raw payload carriage in LEEF/CEF output
- Documented the new format options and transport guidance in the configuration section

## Fork Release Notes

Current fork release highlights:
- Introduced `LEEF` output for QRadar-style syslog ingestion
- Added outbound format switching with `IMPERVA_SYSLOG_FORMAT`
- Added JSON-to-CEF conversion for tenants now returning JSON logs
- Added raw JSON file normalization so pretty JSON and JSON arrays are forwarded as one event per log record
- Hardened TCP syslog writes for larger events with `sendall()`
- Added guidance and warnings around UDP truncation risk for oversized syslog messages

- [CHANGELOG](https://github.com/imperva/incapsula-logs-downloader/blob/master/CHANGELOG.md)  
- [DEPENDENCIES](#dependencies)
- [GETTING STARTED](#getting-started)  
- [EXECUTING THE SCRIPT](#executing-the-script)
- [RUNNING THE SCRIPT AS A SERVICE](#running-the-script-as-a-service)
	- [SysVinit](#sysvinit)
- [DOCKER](#docker)  
	- [Configuration](#configuration)  
	- [Encrypted Logs](#encrypted-logs)

## Dependencies

> This script requires Python 3
The script has the following pythondependencies that may require additional installation modules, according to the operating system that is used.
# Note: the encryption libraries are not needed if decryption is not being used.

- **pycryptodome**
- **M2Crypto**

A requirements.txt file is included in the script directory, so that the following can be used to install requirements and dependencies:

```
pip install -r requirements.txt
```

## Getting Started

- Create a local folder for holding the script configuration, this will be referred as **path_to_config_folder**
	- copy the Settings.Config file to this folder
	- Create a subfolder named **keys** under the **path_to_config_folder** folder 
	- In the keys subfolder, create a subfolder with a single digit name. This digit should specify whether this is the first encryption key uploaded (1), the second (2) or so on
	- Inside that folder, save the private key with the name **Private.key**:

## Executing The Script

An example for calling the script is below:

```
python LogsDownloader.py \
  -c path_to_config_folder \
  -l path_to_system_logs_folder \
  -v system_logs_level
```

- The **-c** and **-l** and **–v** parameters are optional
- The default value for **path_to_config_folder** is **/etc/incapsula/logs/config**
- The default value for **path_to_system_logs_folder** is **/var/log/incapsula/logsDownloader/**
- The default value for **system_logs_level** is **info**
- The **path_to_system_logs_folder** is the folder where the script output log file is stored. **NOTE**: This is for the script output only. The location to store the CloudWAF logs is defined in the Settings.Config file or IMPERVA_INCOMING_DIR, IMPERVA_PROCESS_DIR, and IMPERVA_ARCHIVE_DIR environment variable.
- The **system_logs_level** configuration parameter holds the logging level for the script output log. The supported levels are **info**, **debug** and **error**
- You can run **`LogsDownloader.py -h`** to get help

## Running The Script As A Service

### SysVinit
You can run the script as a service on Linux systems by using the configuration file - **linux_service_configuration/incapsulaLogs.conf**

You should modify the following parameters in the configuration file according to your environment:
1. **`$USER$`** - The user that will execute the script
2. **`$GROUP$`** - The group name that will execute the script
3. **`$PYTHON_SCRIPT$`** - The path to the **`LogsDownloader.py`** file, followed by the parameters for execution of the script

On your system, copy the **incapsulaLogs.conf** file and place it under the **/etc/init/** directory
```
sudo cp incapsulaLogs.conf /etc/init/incapsulaLogs.conf
sudo initctl reload-configuration
sudo ln -s /etc/init/incapsulaLogs.conf /etc/init.d/incapsulaLogs
sudo service incapsulaLogs start
```

You can use `start/stop/status` as any other Linux service

## Docker

A dockerfile is provided to build your own image locally. At this time, a dockerhub image is not available.

### Docker Compose

The included `docker-compose.yml` runs the downloader with the same forwarding behavior used in local testing:

- downloaded payload files are written to container `tmpfs` paths
- processed payload files are deleted after successful syslog forwarding
- `complete.log`, `logs.index`, `sent.log`, and other small state files persist in the `incapsula-config` named volume
- raw JSON input is normalized before forwarding, so JSON arrays and pretty JSON files do not split across syslog records
- LEEF records are sent as newline-delimited records wrapped in an RFC3164 syslog header (`<pri> timestamp hostname LEEF:1.0|...`)

Create a production environment file:

```
cp .env.example .env
```

Edit `.env` and set the Imperva API values and reachable SIEM/syslog target:

```
IMPERVA_API_ID=...
IMPERVA_API_KEY=...
IMPERVA_API_URL=https://logs1.incapsula.com/123456_456789/
IMPERVA_SYSLOG_ADDRESS=10.0.10.25
IMPERVA_SYSLOG_PORT=514
IMPERVA_SYSLOG_PROTO=TCP
SYSLOG_TCP_FRAMING=newline
IMPERVA_SYSLOG_FORMAT=LEEF
```

Start the service:

```
docker compose up -d --build
docker compose logs -f incapsula-log-downloader
```

Do not use `127.0.0.1` for `IMPERVA_SYSLOG_ADDRESS` in production unless the syslog receiver is inside the same container. If the receiver is on the Docker host, use `host.docker.internal` or the host IP reachable from the container. If the receiver is a SIEM, use the SIEM IP address or DNS name reachable from the Docker network.

### Configuration

The connector script will look for the following environment variables, and fall back to the configuration file if the environment variable is not set:

* IMPERVA_API_KEY (required) - API creds that are found on your account page: https://management.service.imperva.com/my/web-logs/settings?caid=XXXXXX  
* IMPERVA_API_ID (required) - API creds that are found on your account page: https://management.service.imperva.com/my/web-logs/settings?caid=XXXXXX
* IMPERVA_API_URL (required) - URL config found on your account page: https://management.service.imperva.com/my/web-logs/settings?caid=XXXXXX
* IMPERVA_INCOMING_DIR (optional) - Directory to download logs temporally and then move to process directory. 
  * Default: current working directory/incoming
* IMPERVA_PROCESS_DIR (optional) - Directory to move downloaded files into for processing; i.e. send to SIEM via HTTP, SYSLOG or Splunk Forwarder.
  * Default: current working directory/process
* IMPERVA_ARCHIVE_DIR (optional) - Directory to archive processed and compressed logs. 
  * Default: current working directory/archive
  * #### NOTE: If IMPERVA_ARCHIVE_DIR is left empty, the logs will be deleted after sending.
* IMPERVA_USE_PROXY (optional) - Use a proxy with "YES". 
  * Default: "NO"
* IMPERVA_PROXY_SERVER (optional) - Use proxy IP address, ex: "192.168.1.19" No default
* IMPERVA_USE_CUSTOM_CA_FILE (optional) - Use a CA certificate for proxy with "YES". 
  * Default: "NO"
* IMPERVA_CUSTOM_CA_FILE (optional, see note below) - Full path to CA certificate, Example: 
  * "/usr/ssl/certs/ca_cert.pem". No default
* IMPERVA_SYSLOG_ENABLE (optional) - Send to syslog with "YES". 
  * Default: "NO"
* IMPERVA_SYSLOG_ADDRESS (optional) - Use syslog server IP address, Example: 
  * "192.168.1.19" No default
* IMPERVA_SYSLOG_PORT (optional) - Use syslog server port, Example: 
  * "514" No default
* IMPERVA_SYSLOG_PROTO (optional) - Use TCP protocol with syslog server, Example: 
  * "TCP" Default: "UDP"
* SYSLOG_TCP_FRAMING (optional) - TCP syslog framing mode. Use "octet" for RFC6587 octet-counted frames or "newline" for receivers that expect one event per line.
  * Default: "octet"
* IMPERVA_SYSLOG_FORMAT (optional) - Syslog payload format to emit. Supported values are "LEEF", "CEF", and "JSON".
  * Default: "LEEF"
  * By default LEEF output is wrapped in an RFC3164 syslog header (`<pri> timestamp hostname LEEF:1.0|...`). The header hostname is the Log Source Identifier the SIEM uses and is taken from `IMPERVA_SYSLOG_SENDER_HOSTNAME`. Set `IMPERVA_LEEF_SYSLOG_HEADER=NO` to emit the bare LEEF record with no header.
  * Raw JSON input files can be compact newline-delimited JSON, a single JSON object, a JSON array, or a JSON object with a top-level `logs`, `events`, or `records` array. Arrays are sent as one syslog event per array element.
* IMPERVA_SYSLOG_SENDER_HOSTNAME (optional) - Hostname placed in the LEEF/CEF syslog header. Set this to your own value (e.g. "incapsula_waf") to use it verbatim. When left at the default the hostname is derived from the event payload.
  * Default: "imperva.com"
* IMPERVA_LEEF_VERSION (optional) - LEEF specification version emitted in the record banner (`LEEF:<version>|...`). Supported values are "1.0" and "2.0".
  * Default: "1.0"
* IMPERVA_LEEF_SYSLOG_HEADER (optional) - Wrap LEEF records in an RFC3164 syslog header. Set to "NO" to send bare `LEEF:...` records with no priority/timestamp/host prefix.
  * Default: "YES"
* IMPERVA_SYSLOG_FACILITY (optional) - Syslog facility used to compute the RFC3164 PRI (facility * 8 + severity, severity fixed at info=6). Accepts a name (e.g. "local0", "daemon", "local4") or a numeric code (0-23).
  * Default: "local0" (PRI `<134>`)
* IMPERVA_SYSLOG_SECURE (optional) - Use TCP/TLS protocol with syslog server with "YES". 
  * Default: "NO"
* Large event note - If you need to avoid truncation for large events, prefer `IMPERVA_SYSLOG_PROTO=TCP` or TCP/TLS. UDP delivery may truncate or drop oversized syslog datagrams due to transport limits.
* IMPERVA_SPLUNK_HEC (optional) - Send to Splunk via HAC with "YES". 
  * Default: "NO"
* IMPERVA_SPLUNK_HEC_IP (optional) - Use splunk server address, IP address or FQDN, Example:
  * "https://192.168.1.19" or "https://http-inputs-unique-host.splunkcloud.com" No default
* IMPERVA_SPLUNK_HEC_PORT (optional) - Use splunk server port, Example: 
  * "8088" No default
* IMPERVA_SPLUNK_HEC_TOKEN (optional) - Use splunk server token, Example: 
  * "B5A79AAD-D822-46CC-80D1-819F80D7BFB0" No default
* IMPERVA_SPLUNK_HEC_SRC_HOSTNAME (optional) - Use to statically assign the hostname where the message was sent from.
* IMPERVA_SPLUNK_HEC_INDEX (optional) - Use to statically assign the splunk index. 
  * Default "imperva" - the Imperva CWAF Dashboard requires this.
* IMPERVA_SPLUNK_HEC_SOURCE (optional) - Use to statically assign the splunk source else splunk will assign the defined index in the HEC config.
* IMPERVA_SPLUNK_HEC_SOURCETYPE (optional) - Use to statically assign the splunk source_type. 
  * Default "imperva:cef" - the Imperva CWAF Dashboard requires this.

> Note - In order to use a custom CA file, you will need to either build a docker image with the file embedded, or mount a persistent data volume to the image and provide the full path to the file as this variable value.

### Encrypted Logs
	
The recommended method would be to mount a persistent data volume at /etc/incapsula/logs/config/keys that contains numbered subfolders with key files as detailed in [Preparations for using the script](#preparations-for-using-the-script).

You can also use the dockerfile in this repo to build the image with your keys baked in.
