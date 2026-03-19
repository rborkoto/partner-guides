# Datadog Monitoring for MFT File Transfers on Windows Servers (v0.9)

## Overview

This guide walks through setting up end-to-end monitoring for Managed File Transfer (MFT) workloads — including Azure MFT — running on Windows servers using Datadog. The primary signal is logs. You do not need APM or custom instrumentation.

By the end of this guide you will be tracking:

- Whether a file has arrived in a directory
- Whether a file has been removed from a directory
- Whether there is a delay in writing a file to a directory
- Transfer duration and latency
- File size trends
- Error counts and retry attempts
- Transfer success and failure rates
- Peak transfer windows
- Real-time alerting on failures or missed transfers

> **Key insight from operations teams:** Not all MFT log lines contain all fields. A common real-world issue is that certain log messages (particularly errors or partial events) arrive without fields such as `size_mb` or `duration_s`. Your pipeline must handle this gracefully with optional attribute rules — see [Step 4](#step-4-create-a-log-parsing-pipeline) for details.

---

## Prerequisites

Before starting, make sure the following are in place:

- Datadog Agent (version 7.x recommended) installed on each Windows server participating in file transfers
- MFT software generating log files to disk or Windows Event Log. Supported tools include:
  - **Azure MFT** (SFTP-enabled Azure Blob Storage or Azure Data Factory transfer pipelines)
  - MOVEit Transfer
  - Axway
  - GoAnywhere
  - GlobalSCAPE EFT
  - WinSCP
  - Custom PowerShell-based transfer scripts
- A Datadog account with Logs and Metrics features enabled
- Access to edit Agent configuration files on the Windows servers
- Log files accessible by the account running the Datadog Agent service (default: `ddagentuser` on Windows)

---

## Architecture Overview

The data flow follows a straightforward path. The Datadog Agent reads log files written by your MFT software, forwards them to Datadog Logs, where a pipeline parses and enriches them. Log-based metrics are then generated from parsed logs and used to power dashboards and monitors.

```
Windows Server A (Source)          Windows Server B (Destination)
        |                                      |
  MFT Process writes logs              MFT Process writes logs
        |                                      |
        +------------------+-------------------+
                           |
                  Datadog Agent (Windows)
                  - Tails log files
                  - Forwards to Datadog
                           |
                           v
                    Datadog Log Intake
                           |
                           v
                  Log Pipeline (Parsing + Enrichment)
                  - Grok Parser (multi-rule, handles partial logs)
                  - Attribute Remapper
                  - Status Remapper
                  - Category Processor
                           |
                           v
                  Log-Based Metrics
                  - mft.files.count
                  - mft.success.count
                  - mft.failure.count
                  - mft.file.size
                  - mft.transfer.duration
                  - mft.error.count
                           |
                  +---------+---------+
                  |                   |
              Dashboards           Monitors
          (KPIs, trends)     (Failure alerts,
                              SLA checks,
                              directory watches)
```

If you are running multiple Windows servers (source and destination), install and configure the Datadog Agent on each one. Tagging logs with `hostname` (added automatically by the Agent) and a custom `transfer_role` tag (`source` or `destination`) will help you filter and correlate across servers in dashboards.

---

## Step 1: Configure the Datadog Agent for Log Collection

The Datadog Agent does not enable log collection by default. You need to turn it on in the main configuration file.

Open the main Agent configuration file:

```
C:\ProgramData\Datadog\datadog.yaml
```

Enable log collection and add environment-level tags:

```yaml
logs_enabled: true

tags:
  - env:production
  - team:mft
  - transfer_role:source
```

After saving, restart the Agent:

```powershell
Restart-Service datadogagent
```

Verify the Agent is healthy:

```powershell
& "C:\Program Files\Datadog\Datadog Agent\bin\agent.exe" status
```

**Reference:** [Agent Configuration Files](https://docs.datadoghq.com/agent/configuration/agent-configuration-files/?tab=agentv6v7)

---

## Step 2: Configure Log Collection for MFT Logs

Create a dedicated configuration directory and file for your MFT log source.

```
C:\ProgramData\Datadog\conf.d\mft_logs.d\conf.yaml
```

The contents depend on how your MFT tool writes logs.

### File-based log collection (most MFT tools)

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer.log
    service: mft
    source: mft
    tags:
      - transfer_role:source
```

For date-rotated log files:

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer_*.log
    service: mft
    source: mft
    tags:
      - transfer_role:source
```

### Azure MFT log collection

If you are using Azure MFT (for example, Azure Data Factory pipeline logs forwarded to a local path, or an SFTP-enabled Azure Blob Storage integration that writes transfer events locally), use the same file-based approach but reference the log output path configured in your Azure MFT agent or connector:

```yaml
logs:
  - type: file
    path: C:\AzureMFT\logs\transfer_*.log
    service: mft
    source: azure_mft
    tags:
      - transfer_role:source
      - cloud_provider:azure
```

> **Azure MFT note:** Azure MFT logs may arrive with varying levels of detail per event type. Some events (for example, `FILE_ARRIVED`) will have a full set of fields, while others (for example, `TRANSFER_QUEUED` or error events) may only include a subset. This is a common reason why pipeline rules fail on certain log lines. See [Step 4](#step-4-create-a-log-parsing-pipeline) for how to handle this.

### Multiple log files (transfer and error logs separate)

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer.log
    service: mft
    source: mft
    log_processing_rules:
      - type: multi_line
        name: new_transfer_entry
        pattern: ^\d{4}-\d{2}-\d{2}

  - type: file
    path: C:\MFT\logs\errors.log
    service: mft
    source: mft-errors
```

The `multi_line` rule handles cases where a single log entry spans multiple lines, which is common in MFT error logs that include stack traces or extended metadata.

After saving, restart the Agent and confirm collection is running:

```powershell
Restart-Service datadogagent
& "C:\Program Files\Datadog\Datadog Agent\bin\agent.exe" status
```

Look for the `Logs Agent` section and confirm your configuration shows as running.

**Reference:** [Log Collection on Windows](https://docs.datadoghq.com/logs/log_collection/windows/)

---

## Step 3: Standardize Your Log Format

The quality of your log-based metrics depends entirely on how consistently your MFT software writes log entries. If you have control over the log format (for example, through a custom PowerShell transfer script or a configurable MFT tool), use a structured format so that parsing is reliable.

### Key-value pair format

```
timestamp=2024-11-15T09:30:00Z file=quarterly_report.csv size_mb=45 status=SUCCESS duration_s=12 source_host=WINSRV-A destination_host=WINSRV-B
```

For failures (note: `size_mb` and `duration_s` are intentionally absent):

```
timestamp=2024-11-15T09:31:00Z file=orders_export.csv status=FAILED error="connection timeout after 30s" source_host=WINSRV-A destination_host=WINSRV-B retry_attempts=3
```

### JSON format (recommended)

JSON logs are automatically parsed by Datadog without requiring a custom Grok rule:

```json
{
  "timestamp": "2024-11-15T09:30:00Z",
  "file": "quarterly_report.csv",
  "size_mb": 45,
  "status": "SUCCESS",
  "duration_s": 12,
  "source_host": "WINSRV-A",
  "destination_host": "WINSRV-B",
  "transfer_id": "txn-00291",
  "retry_attempts": 0
}
```

For errors, include as many fields as available. The pipeline will handle missing optional fields:

```json
{
  "timestamp": "2024-11-15T09:31:00Z",
  "file": "orders_export.csv",
  "status": "FAILED",
  "error": "connection timeout after 30s",
  "source_host": "WINSRV-A",
  "destination_host": "WINSRV-B",
  "retry_attempts": 3
}
```

### PowerShell script with structured JSON logging

If you are using a PowerShell script for file transfers, here is a pattern that always logs a consistent set of fields regardless of outcome:

```powershell
$transferStart = Get-Date
$file = "quarterly_report.csv"
$sourceHost = $env:COMPUTERNAME
$destinationHost = "WINSRV-B"
$retryAttempts = 0

try {
    Copy-Item "C:\outbound\$file" "\\$destinationHost\incoming\$file"

    $duration = ((Get-Date) - $transferStart).TotalSeconds
    $fileSize = (Get-Item "C:\outbound\$file").Length / 1MB

    $logEntry = @{
        timestamp        = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        file             = $file
        size_mb          = [math]::Round($fileSize, 2)
        status           = "SUCCESS"
        duration_s       = [math]::Round($duration, 2)
        source_host      = $sourceHost
        destination_host = $destinationHost
        retry_attempts   = $retryAttempts
    } | ConvertTo-Json -Compress

    Add-Content -Path "C:\MFT\logs\transfer.log" -Value $logEntry

} catch {
    $logEntry = @{
        timestamp        = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        file             = $file
        status           = "FAILED"
        error            = $_.Exception.Message
        source_host      = $sourceHost
        destination_host = $destinationHost
        retry_attempts   = $retryAttempts
        # Note: size_mb and duration_s are deliberately omitted on failure
        # The pipeline is designed to handle their absence
    } | ConvertTo-Json -Compress

    Add-Content -Path "C:\MFT\logs\transfer.log" -Value $logEntry
}
```

---

## Step 4: Create a Log Parsing Pipeline

If your logs are in JSON format, Datadog parses all fields automatically and you can skip directly to the remapper processors below. If your logs are in key-value or a custom text format, you will need a Grok parser.

Navigate to **Logs > Configuration > Pipelines** and create a new pipeline with the filter `service:mft`.

> **Important:** In real-world MFT deployments, different event types produce log lines with different fields. For example, Azure MFT logs may include full metadata for `FILE_TRANSFERRED` events but only a timestamp, status, and error message for `FILE_FAILED` events. **You must write multiple Grok rules — one per log shape — so that each rule only needs to match the fields that are actually present in that log type.** A rule that expects `size_mb` will fail to match any failure log that omits it.

### Processor 1: Grok Parser

Add a Grok Parser processor. Each line is one rule; the parser tries them in order and uses the first match.

**Rule 1 — Successful transfer (all fields present):**

```
mft_success timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} size_mb=%{integer:size_mb} status=%{word:transfer_status} duration_s=%{number:duration_s} source_host=%{notSpace:source_host} destination_host=%{notSpace:destination_host}
```

**Rule 2 — Failed transfer with retry count (no size or duration):**

```
mft_failure timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} status=%{word:transfer_status} error="%{data:error_message}" source_host=%{notSpace:source_host} destination_host=%{notSpace:destination_host} retry_attempts=%{integer:retry_attempts}
```

**Rule 3 — Failed transfer without retry count:**

```
mft_failure_simple timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} status=%{word:transfer_status} error="%{data:error_message}" source_host=%{notSpace:source_host} destination_host=%{notSpace:destination_host}
```

**Rule 4 — Minimal event (status and timestamp only, common in certain Azure MFT log types):**

```
mft_minimal timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} status=%{word:transfer_status}
```

Add all rules in the same Grok parser processor, one per line. Rules are evaluated top to bottom — place the most specific rules first.

> **Debugging tip:** If certain log messages are still not being parsed after your pipeline is set up, use the **Pipeline Scanner** (Logs > Pipelines > Pipeline Scanner) to trace a specific log through every pipeline and processor. This shows exactly which rule matched or failed. You can also paste raw log samples into the Grok parser's built-in debugger to test rules interactively.

### Processor 2: Date Remapper

Add a Date Remapper and set the source attribute to `transfer_timestamp`. This ensures the log timestamp reflects the actual transfer time, not the Datadog ingestion time.

> **Note:** If timestamps appear shifted or offset, your MFT server may be logging in a local timezone rather than UTC. In the Grok parser rule, you can specify the timezone as part of the date matcher, for example: `%{date("yyyy-MM-dd'T'HH:mm:ss'Z'","Europe/London"):transfer_timestamp}`. See [Parsing dates](https://docs.datadoghq.com/logs/log_configuration/parsing/?tab=matchers#parsing-dates) for supported timezone identifiers.

### Processor 3: Category Processor

Before applying the Status Remapper, add a Category Processor to map your MFT-specific status values to Datadog standard log levels:

| If `transfer_status` matches | Set `log_status` to |
|---|---|
| `SUCCESS` | `info` |
| `FAILED` | `error` |
| `WARNING` | `warning` |
| `QUEUED` | `notice` |

### Processor 4: Status Remapper

Add a Status Remapper and point it at the `log_status` attribute produced by the Category Processor above. This enables status-based filtering, colouring, and log level monitors in the Log Explorer.

**Reference:** [Log Pipelines and Parsing](https://docs.datadoghq.com/logs/log_configuration/parsing/)

---

## Step 5: Enrich Logs Before Building Metrics

A critical prerequisite for log-based metrics is that the logs contain the information needed to generate them. Before creating metrics, verify that your parsed logs include the following:

| Field | Required for | Notes |
|---|---|---|
| `transfer_status` | Success/failure metrics | Must be present on every log entry |
| `file_name` | File-level tracking | |
| `size_mb` | File size metrics | May be absent on failure logs — expected |
| `duration_s` | Latency metrics | May be absent on failure logs — expected |
| `source_host` | Per-host breakdown | Added automatically by the Agent if not in the log |
| `destination_host` | Per-destination breakdown | |
| `error_message` | Error investigation | Only needed on failure logs |
| `retry_attempts` | Retry tracking | Add this to your log format if your MFT tool supports it |

If a required field is missing from your raw logs, you have two options:

1. **Enrich at source:** Update your MFT tool's log configuration or your PowerShell script to include the missing field.
2. **Enrich in the pipeline:** If the information is available elsewhere (for example, hostname in the Agent metadata), use a Remapper or String Builder processor to derive or copy it into the expected attribute.

> **From support experience:** The most common enrichment gap is logs that do not include an explicit `transfer_status` field on every event. If the absence of a status field causes a Grok rule to fail to match, that log will not contribute to your metrics. Always verify in the Log Explorer that both success and failure logs are being parsed correctly before building metrics.

**Reference:** [Log Processors](https://docs.datadoghq.com/logs/log_configuration/processors/)

---

## Step 6: Create Log-Based Metrics

Log-based metrics allow you to generate time-series metrics from parsed log data without storing every log event forever.

Navigate to **Logs > Generate Metrics**.

### Metric: mft.files.count

Counts every transfer attempt.

```
Filter:   service:mft
Name:     mft.files.count
Type:     count
Group by: source_host, destination_host
```

### Metric: mft.success.count

```
Filter:   service:mft @transfer_status:SUCCESS
Name:     mft.success.count
Type:     count
Group by: source_host, destination_host
```

### Metric: mft.failure.count

```
Filter:   service:mft @transfer_status:FAILED
Name:     mft.failure.count
Type:     count
Group by: source_host, destination_host
```

### Metric: mft.error.count

Tracks all error-level log events, including those that may not have an explicit `transfer_status:FAILED` attribute:

```
Filter:   service:mft status:error
Name:     mft.error.count
Type:     count
Group by: source_host, destination_host
```

### Metric: mft.retry.count

Tracks retry attempts across all transfer events:

```
Filter:   service:mft @retry_attempts:>0
Name:     mft.retry.count
Type:     distribution
Field:    @retry_attempts
Group by: source_host, destination_host
```

### Metric: mft.file.size

Tracks the distribution of file sizes.

```
Filter:   service:mft @transfer_status:SUCCESS
Name:     mft.file.size
Type:     distribution
Field:    @size_mb
Group by: source_host, destination_host
```

### Metric: mft.transfer.duration

Tracks transfer latency.

```
Filter:   service:mft @transfer_status:SUCCESS
Name:     mft.transfer.duration
Type:     distribution
Field:    @duration_s
Group by: source_host, destination_host
```

> **Note:** The `@` prefix in filter queries refers to parsed log attributes. Fields without `@` — such as `service:mft` or `status:error` — are reserved attributes or facets.

> **Note:** Log-based metrics only generate data from logs ingested **after** the metric is created. Wait for new transfer events to arrive before verifying metric data in dashboards.

**Reference:** [Log-Based Metrics](https://docs.datadoghq.com/logs/logs_to_metrics/)

---

## Step 7: Build a Monitoring Dashboard

Navigate to **Dashboards > New Dashboard** and create a dashboard named "MFT Transfer Health".

### Widget: Total Files Transferred (Timeseries)

```
sum:mft.files.count{*}.as_count()
```

Group by `source_host` to break down by server.

### Widget: Transfer Success Rate (Query Value)

```
( sum:mft.success.count{*}.as_count() / sum:mft.files.count{*}.as_count() ) * 100
```

Set a conditional format: red below 95, yellow below 99, green above 99.

### Widget: Transfer Failures (Timeseries)

```
sum:mft.failure.count{*}.as_count()
```

Set the y-axis to start at 0. Any bar above zero warrants investigation.

### Widget: Error Count (Timeseries)

```
sum:mft.error.count{*}.as_count()
```

Use this alongside the failure count widget. A gap between the two indicates log events with error status that were not captured by the `transfer_status:FAILED` filter — a signal that your pipeline may need additional Grok rules.

### Widget: Average Transfer Duration with p95 (Timeseries)

```
avg:mft.transfer.duration{*}
p95:mft.transfer.duration{*}
```

### Widget: Retry Attempts (Timeseries)

```
sum:mft.retry.count{*}.as_count()
```

A rising retry rate often precedes an outright failure and is a useful early warning signal.

### Widget: File Size Distribution

```
avg:mft.file.size{*}
```

### Widget: Peak Transfer Windows (Timeseries with hourly rollup)

```
sum:mft.files.count{*}.rollup(sum, 3600)
```

### Widget: Failure Log Stream

Add a Log Stream widget filtered to `service:mft @transfer_status:FAILED` so that on-call engineers can see recent failure details without leaving the dashboard.

### Widget: Directory Monitoring (File Arrival / Removal)

If your MFT pipeline must track whether files arrive or are removed from specific directories, add a Log Stream widget filtered to the relevant directory path attribute:

```
service:mft @directory_path:/path/to/watched/directory
```

This is only useful if your MFT tool logs directory-level events. If it does not, see the [Directory Monitoring with Process Agent](#appendix-directory-monitoring-with-the-process-agent) appendix.

**Reference:** [Dashboards](https://docs.datadoghq.com/dashboards/)

---

## Step 8: Configure Monitors and Alerts

### Monitor 1: Transfer Failure Detected

```
Monitor type: Metric Alert
Query:        sum(last_5m):sum:mft.failure.count{*}.as_count() > 0
Alert:        > 0
Notify:       @pagerduty-mft-oncall @slack-mft-alerts
Title:        [MFT] Transfer failure detected on {{source_host.name}}
Message:      One or more file transfer failures have been recorded in the last 5 minutes.
              Check the MFT dashboard and Log Explorer for details.
              Affected host: {{source_host.name}}
```

### Monitor 2: No Transfers Detected (Dead Man's Switch)

```
Monitor type: Metric Alert
Query:        sum(last_30m):sum:mft.files.count{*}.as_count() < 1
Alert:        < 1
Notify:       @slack-mft-alerts
Title:        [MFT] No transfers detected in the last 30 minutes
Message:      No file transfer events have been logged in the last 30 minutes.
              This may indicate the MFT process has stopped, or log collection is broken.
```

Use the monitor scheduling option to limit evaluation to your expected transfer windows and avoid false alerts during off-hours.

### Monitor 3: Transfer Duration Anomaly

```
Monitor type: Metric Alert
Query:        avg(last_10m):avg:mft.transfer.duration{*} > 300
Alert:        > 300
Warning:      > 180
Notify:       @slack-mft-alerts
Title:        [MFT] High transfer duration detected
Message:      Average transfer duration over the last 10 minutes has exceeded 300 seconds.
              This may indicate network congestion, destination server issues, or large file volumes.
```

### Monitor 4: Success Rate Below Threshold

```
Monitor type: Metric Alert
Query:        (sum(last_15m):sum:mft.success.count{*}.as_count() /
               sum(last_15m):sum:mft.files.count{*}.as_count()) * 100 < 95
Alert:        < 95
Warning:      < 99
Title:        [MFT] Transfer success rate has dropped below 95%
```

### Monitor 5: Elevated Retry Attempts

```
Monitor type: Metric Alert
Query:        sum(last_15m):sum:mft.retry.count{*}.as_count() > 10
Alert:        > 10
Warning:      > 5
Notify:       @slack-mft-alerts
Title:        [MFT] Elevated retry attempts detected
Message:      Transfer retry attempts are elevated. This often precedes transfer failures.
              Check destination host availability and network connectivity.
```

**Reference:** [Monitors](https://docs.datadoghq.com/monitors/)

---

## Step 9: Windows Event Log Collection (Optional)

Many enterprise MFT tools write events to the Windows Application Event Log in addition to file-based logs.

Create or open:

```
C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml
```

```yaml
logs:
  - type: windows_event
    channel_path: Application
    source: windows.events
    service: mft
    log_processing_rules:
      - type: include_at_match
        name: include_mft_events
        pattern: "MOVEit|Axway|GoAnywhere|FileTransfer|MFT|AzureMFT"
```

For a custom event channel:

```yaml
logs:
  - type: windows_event
    channel_path: MOVEit Transfer
    source: moveit
    service: mft
```

Restart the Agent after making this change.

**Reference:** [Windows Event Log Integration](https://docs.datadoghq.com/integrations/windows_event_log/)

---

## Troubleshooting

### Logs are not appearing in Datadog

Run the Agent status command and look for errors in the Logs Agent section:

```powershell
& "C:\Program Files\Datadog\Datadog Agent\bin\agent.exe" status
```

**Common causes:**

- The log file path in `conf.yaml` does not exist or is misspelled
- The Datadog Agent service account does not have read access to the log file
- `logs_enabled: true` is missing or commented out in `datadog.yaml`
- The log file is currently empty (the Agent will not report errors for empty files)

To grant read access to the log directory:

```powershell
$acl = Get-Acl "C:\MFT\logs"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT SERVICE\datadogagent", "Read", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\MFT\logs" $acl
```

### Certain log messages are not being parsed by the pipeline

This is a common issue when different MFT event types produce log lines with different fields. The symptom is that some logs appear in the Log Explorer without parsed attributes (for example, missing `transfer_status` or `size_mb`).

**Resolution steps:**

1. Open **Logs > Pipelines > Pipeline Scanner** and query `service:mft` to see which rules are matching each log type.
2. Open the Grok Parser processor and paste the unparsed log line into the sample debugger to see why your rules are not matching.
3. Add a new Grok rule that matches the shape of the failing log line. Make all fields that are not always present optional by wrapping them in `(%{...})?` patterns.
4. Place the new rule in the correct position — more specific rules should come before more general ones.

Example of a rule with optional fields:

```
mft_event timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} status=%{word:transfer_status}( size_mb=%{integer:size_mb})?( duration_s=%{number:duration_s})?( error="%{data:error_message}")?
```

### Grok parser is not extracting any fields

Use the Grok debugger in the Datadog UI: navigate to **Logs > Configuration > Pipelines**, open your pipeline, and click the Grok parser processor. Paste a raw log line into the debugger and check which fields are being extracted.

If no fields are extracted, check that your Grok rule pattern matches the exact format of your log line, including whitespace and special characters.

### Log-based metrics show no data

After creating a log-based metric, it only generates data from **new** incoming logs. Wait for new transfers to occur and verify logs are arriving in the Log Explorer before troubleshooting the metric.

Confirm that the filter in your metric definition uses the correct syntax. For parsed attributes, prefix the attribute name with `@`. For example, use `@transfer_status:SUCCESS` rather than `transfer_status:SUCCESS`.

### Timestamps showing ingestion time instead of transfer time

The Date Remapper is either missing or pointing at the wrong attribute name. Double-check that the attribute name in the Date Remapper matches exactly what the Grok parser is outputting, including case sensitivity. Verify in the Log Explorer by expanding a parsed log and confirming the `transfer_timestamp` attribute is present.

### Grok rule matches some log samples but not others (multi-line records)

If certain log samples show **NO MATCH** in the Grok parser debugger while structurally similar ones match fine, the failing sample likely contains a **newline character mid-record**. This happens when an MFT tool wraps long lines (for example, a long Windows UNC path) across two physical lines in the log file. The Grok parser processes one line at a time by default, so a record split across lines will never match.

**Fix:** Configure the Datadog Agent to merge continuation lines into a single record before forwarding. In your `conf.yaml`, add a `multi_line` processing rule that identifies where a new record begins:

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer.log
    service: mft
    source: mft
    log_processing_rules:
      - type: multi_line
        name: mft_record_start
        pattern: ^;\s*\d+
```

This pattern (`^;\s*\d+`) matches lines that start with `; <number>` — the beginning of a new MFT transfer record. Lines that do not match (such as a wrapped path continuation) are appended to the previous record, so the Grok parser receives the full record as a single string.

Adjust the pattern to match whatever consistently marks the start of a record in your specific log format.

**Reference:** [Multi-line log aggregation](https://docs.datadoghq.com/agent/logs/advanced_log_collection/#multi-line-aggregation)

### Logs appear in Datadog with NUL bytes between every character

If you open a log in the Log Explorer and see `NUL` characters between every letter, or the Grok parser fails to match records that look structurally correct, the log file likely contains **null bytes** (`\x00`). This is common with Windows MFT tools that write logs in UTF-16 — each character is two bytes, and when the Agent reads the file as UTF-8 the second byte of each pair appears as a null character. The result is a message like `;` `\x00` `7` `\x00` `2` `\x00` `2` `\x00` `;` which no Grok rule will match.

**Symptoms:**
- Some log records parse correctly while others show NUL characters
- The Grok parser fails to extract any fields even though the rule is correct
- The raw message in Log Explorer looks like double-spaced or garbled text

**Fix — strip null bytes at the Agent using `mask_sequences`:**

Datadog recommends cleaning invalid characters at the Agent level before logs reach the parsing pipeline. The `mask_sequences` processing rule replaces any regex match with a placeholder string — set the placeholder to `""` to delete the matched characters entirely. Agent-side processing rules use Go regexp syntax.

Add the following to your `conf.yaml`:

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer.log
    service: mft
    source: mft
    log_processing_rules:
      - type: mask_sequences
        name: strip_null_bytes
        pattern: \x00+
        replace_placeholder: ""
```

This converts `;` `\x00` `7` `\x00` `2` `\x00` `2` `\x00` `;` into `;722;` before the log reaches your Grok parser.

**If collecting from Docker or Kubernetes**, the same rule goes into the container label or pod annotation:

```json
# Docker label
com.datadoghq.ad.logs: '[{"type":"file","path":"/path/to/transfer.log","service":"mft","source":"mft","log_processing_rules":[{"type":"mask_sequences","name":"strip_null_bytes","pattern":"\\x00+","replace_placeholder":""}]}]'
```

```yaml
# Kubernetes pod annotation
ad.datadoghq.com/<container>.logs: |
  [{"type":"file","path":"/path/to/transfer.log","service":"mft","source":"mft",
  "log_processing_rules":[{"type":"mask_sequences","name":"strip_null_bytes","pattern":"\\\\x00+","replace_placeholder":""}]}]
```

Note that backslashes must be escaped in labels and annotations — `\x00` becomes `\\x00` in JSON labels and `\\\\x00` in YAML annotations.

**If using Observability Pipelines**, use a Custom Processor transform to rewrite the field before forwarding logs onward. This is appropriate for more advanced transformations, but for raw invalid characters in log messages, Agent-side cleanup via `mask_sequences` is the simpler and recommended first step.

> **Preferred long-term fix:** If you have control over the MFT tool's log output settings, configure it to write logs in **UTF-8**. This eliminates the problem at source without requiring any Agent-side workaround.

**Reference:** [Advanced Log Collection — Scrub sensitive data](https://docs.datadoghq.com/agent/logs/advanced_log_collection/#scrub-sensitive-data-from-your-logs)

---

## Best Practices

**Ensure every log event contains a status field.** Without an explicit status field in every log entry, you cannot reliably generate success and failure metrics. This is the most common gap encountered when onboarding MFT workloads.

**Write one Grok rule per log shape, not one rule for all shapes.** MFT tools often write structurally different log lines for different event types. A single Grok rule attempting to handle all variations with optional fields becomes fragile. Separate rules, ordered from most specific to most general, are more maintainable and easier to debug.

**Use structured logs.** JSON is preferred. If your MFT tool cannot produce JSON, key-value format is the next best option. Avoid free-form text log entries for transfer events.

**Include file size, duration, and retry count in every transfer log.** These fields are required for the performance and reliability metrics. Omit them from error logs intentionally and document that your pipeline is designed to handle their absence.

**Use consistent tagging.** Apply `service:mft` to all MFT log sources. Use additional tags such as `source_host`, `destination_host`, `env`, and `cloud_provider` to make dashboards and alerts filterable across environments.

**Set up both failure detection and the dead man's switch monitor.** The failure monitor catches active problems; the "no transfers detected" monitor catches situations where the MFT process has stopped silently.

**Test your alert routing before you need it.** Send a test notification through each monitor to confirm PagerDuty, Slack, or email integrations are working correctly.

**Validate your pipeline against real logs before building metrics.** Use the Pipeline Scanner or the Grok debugger to confirm that all expected log types are being parsed correctly. Do not proceed to metric creation until the Log Explorer shows fully parsed attributes on both success and failure logs.

---

## Summary

| Capability | Datadog Feature |
|---|---|
| Collecting transfer events | Logs Agent on Windows |
| Parsing log fields (including partial logs) | Log Pipeline with multi-rule Grok Parser |
| Tracking KPIs over time | Log-Based Metrics |
| Tracking error and retry trends | Log-Based Metrics (`mft.error.count`, `mft.retry.count`) |
| Visualizing transfer health | Dashboards |
| Alerting on failures | Metric Monitor |
| Alerting on missed transfers | Metric Monitor (below threshold) |
| Alerting on elevated retries | Metric Monitor |
| Debugging pipeline issues | Pipeline Scanner, Grok Debugger |
| Raw log investigation | Log Explorer |

This approach requires no application code changes, no APM instrumentation, and no custom exporters. The Datadog Agent reads the log files your MFT software already produces, and the pipeline and metrics layer turns those logs into actionable observability.

---

## Appendix: Directory Monitoring with the Process Agent

If your MFT tool does not log directory-level events (file arrival, file removal, write delay), you can track these scenarios using Datadog's file integrity monitoring or by adding custom log lines from a scheduled PowerShell watcher script.

### Option A: Custom directory watcher (PowerShell)

Run this as a scheduled task to log file arrival events:

```powershell
$watchPath = "C:\MFT\incoming"
$logPath   = "C:\MFT\logs\directory_events.log"
$interval  = 60  # seconds between checks

while ($true) {
    $files = Get-ChildItem -Path $watchPath
    foreach ($file in $files) {
        $logEntry = @{
            timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            event_type     = "FILE_ARRIVED"
            file           = $file.Name
            size_mb        = [math]::Round($file.Length / 1MB, 2)
            directory_path = $watchPath
            status         = "INFO"
        } | ConvertTo-Json -Compress
        Add-Content -Path $logPath -Value $logEntry
    }
    Start-Sleep -Seconds $interval
}
```

Collect this log file with the Datadog Agent by adding it to your `conf.yaml`:

```yaml
logs:
  - type: file
    path: C:\MFT\logs\directory_events.log
    service: mft
    source: mft
    tags:
      - event_type:directory_watch
```

### Option B: File Integrity Monitoring (FIM)

For environments with Datadog's Security product enabled, you can use [File Integrity Monitoring](https://docs.datadoghq.com/security/cloud_security_management/guide/file-integrity-monitoring/) to detect file creation and deletion events in watched directories without writing a custom script.

---

## Reference Links

- [Datadog Agent on Windows](https://docs.datadoghq.com/agent/basic_agent_usage/windows/)
- [Log Collection on Windows](https://docs.datadoghq.com/logs/log_collection/windows/)
- [Log Pipeline and Parsing](https://docs.datadoghq.com/logs/log_configuration/parsing/)
- [Log Processors](https://docs.datadoghq.com/logs/log_configuration/processors/)
- [Pipeline Scanner](https://docs.datadoghq.com/logs/log_configuration/pipeline_scanner/)
- [Log-Based Metrics](https://docs.datadoghq.com/logs/logs_to_metrics/)
- [Dashboards](https://docs.datadoghq.com/dashboards/)
- [Monitors](https://docs.datadoghq.com/monitors/)
- [Windows Event Log Integration](https://docs.datadoghq.com/integrations/windows_event_log/)
- [Log Processing Rules](https://docs.datadoghq.com/agent/logs/advanced_log_collection/)
- [Parsing Dates](https://docs.datadoghq.com/logs/log_configuration/parsing/?tab=matchers#parsing-dates)
