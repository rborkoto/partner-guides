# Datadog Monitoring for MFT File Transfers on Windows Servers

## Overview

This guide walks through setting up end-to-end monitoring for Managed File Transfer (MFT) workloads running on Windows servers using Datadog. The primary signal here is logs. You do not need APM or custom instrumentation. By collecting and parsing MFT logs through the Datadog Agent, you can build log-based metrics, dashboards, and alerts that give you full visibility into transfer health, performance, and failures.

By the end of this guide you will be tracking:

- Number of files transferred
- Transfer success and failure rates
- File size trends
- Transfer duration and latency
- Peak transfer windows
- Real-time alerting on failures or missed transfers

---

## Prerequisites

Before starting, make sure the following are in place:

- Datadog Agent (version 7.x recommended) installed on each Windows server participating in file transfers
- MFT software generating log files to disk or Windows Event Log (examples include MOVEit Transfer, Axway, GoAnywhere, GlobalSCAPE EFT, WinSCP, or custom PowerShell-based transfer scripts)
- A Datadog account with Logs and Metrics features enabled
- Access to edit Agent configuration files on the Windows servers
- Log files accessible by the account running the Datadog Agent service (default: `ddagentuser` on Windows)

---

## Architecture Overview

The data flow for this integration follows a straightforward path. The Datadog Agent reads log files written by your MFT software, forwards them to Datadog Logs, where a pipeline parses and enriches them. Log-based metrics are then generated from those parsed logs and used to power dashboards and monitors.

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
                  Log Pipeline (Parsing)
                  - Grok Parser
                  - Attribute Remapper
                  - Status Remapper
                           |
                           v
                  Log-Based Metrics
                  - mft.files.count
                  - mft.success.count
                  - mft.failure.count
                  - mft.file.size
                  - mft.transfer.duration
                           |
                  +---------+---------+
                  |                   |
              Dashboards           Monitors
          (KPIs, trends)     (Failure alerts,
                              SLA checks)
```

If you are running multiple Windows servers (source and destination), install and configure the Datadog Agent on each one. Tagging logs with a `hostname` attribute (which the Agent adds automatically) and a custom `transfer_role` tag (source or destination) will help you filter and correlate across servers in dashboards.

---

## Step 1: Configure the Datadog Agent for Log Collection

The Datadog Agent does not enable log collection by default. You need to turn it on in the main configuration file.

Open the main Agent configuration file:

```
C:\ProgramData\Datadog\datadog.yaml
```

Enable log collection by adding or uncommenting the following line:

```yaml
logs_enabled: true
```

If your MFT servers are tagged by environment or team, this is a good place to add global tags that will apply to all data collected by this Agent:

```yaml
logs_enabled: true

tags:
  - env:production
  - team:mft
  - transfer_role:source
```

After saving the file, restart the Agent:

```powershell
Restart-Service datadogagent
```

To verify the Agent is healthy after restart:

```powershell
& "C:\Program Files\Datadog\Datadog Agent\bin\agent.exe" status
```

**Reference:** [Agent Configuration Files](https://docs.datadoghq.com/agent/configuration/agent-configuration-files/?tab=agentv6v7)

---

## Step 2: Configure Log Collection for MFT Logs

Create a dedicated configuration directory and file for your MFT log source. Datadog Agent uses the `conf.d` directory for integration and custom log configurations.

Create the following directory if it does not exist:

```
C:\ProgramData\Datadog\conf.d\mft_logs.d\
```

Create the configuration file:

```
C:\ProgramData\Datadog\conf.d\mft_logs.d\conf.yaml
```

The contents of this file depend on how your MFT tool writes logs. Below are configurations for the most common scenarios.

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

If your MFT tool rolls logs by date and writes to files with a date suffix, you can use a wildcard path:

```yaml
logs:
  - type: file
    path: C:\MFT\logs\transfer_*.log
    service: mft
    source: mft
    tags:
      - transfer_role:source
```

### Multiple log files from the same MFT instance

If your MFT tool writes transfer logs and error logs to separate files, collect both:

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

The `multi_line` processing rule handles cases where a single log entry spans multiple lines, which is common in some MFT error logs that include stack traces or extended metadata.

After saving the configuration file, restart the Agent:

```powershell
Restart-Service datadogagent
```

To confirm the Agent is picking up your log file:

```powershell
& "C:\Program Files\Datadog\Datadog Agent\bin\agent.exe" status
```

Look for the `Logs Agent` section in the output and confirm your configuration shows as running.

**Reference:** [Log Collection on Windows](https://docs.datadoghq.com/logs/log_collection/windows/)

---

## Step 3: Standardize Your Log Format

The quality of your log-based metrics depends entirely on how consistently your MFT software writes log entries. If you have control over the log format (for example, through a custom PowerShell transfer script or a configurable MFT tool), use a structured format so that parsing is reliable and fields do not require complex regex.

There are two recommended formats.

### Key-value pair format

This format is easy to read and straightforward to parse with Datadog's Grok parser:

```
timestamp=2024-11-15T09:30:00Z file=quarterly_report.csv size_mb=45 status=SUCCESS duration_s=12 source_host=WINSRV-A destination_host=WINSRV-B
```

For failures:

```
timestamp=2024-11-15T09:31:00Z file=orders_export.csv status=FAILED error="connection timeout after 30s" source_host=WINSRV-A destination_host=WINSRV-B
```

### JSON format (recommended)

JSON logs are automatically parsed by Datadog without requiring a custom Grok rule. If your MFT tool or script can output JSON, this is the preferred approach:

```json
{
  "timestamp": "2024-11-15T09:30:00Z",
  "file": "quarterly_report.csv",
  "size_mb": 45,
  "status": "SUCCESS",
  "duration_s": 12,
  "source_host": "WINSRV-A",
  "destination_host": "WINSRV-B",
  "transfer_id": "txn-00291"
}
```

If you are using a PowerShell script for file transfers and want to generate structured JSON logs, here is a basic pattern:

```powershell
$transferStart = Get-Date
$file = "quarterly_report.csv"
$sourceHost = $env:COMPUTERNAME
$destinationHost = "WINSRV-B"

try {
    # Your transfer logic here (Copy-Item, robocopy, SFTP, etc.)
    Copy-Item "C:\outbound\$file" "\\$destinationHost\incoming\$file"

    $duration = ((Get-Date) - $transferStart).TotalSeconds
    $fileSize = (Get-Item "C:\outbound\$file").Length / 1MB

    $logEntry = @{
        timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        file           = $file
        size_mb        = [math]::Round($fileSize, 2)
        status         = "SUCCESS"
        duration_s     = [math]::Round($duration, 2)
        source_host    = $sourceHost
        destination_host = $destinationHost
    } | ConvertTo-Json -Compress

    Add-Content -Path "C:\MFT\logs\transfer.log" -Value $logEntry

} catch {
    $logEntry = @{
        timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        file           = $file
        status         = "FAILED"
        error          = $_.Exception.Message
        source_host    = $sourceHost
        destination_host = $destinationHost
    } | ConvertTo-Json -Compress

    Add-Content -Path "C:\MFT\logs\transfer.log" -Value $logEntry
}
```

---

## Step 4: Create a Log Parsing Pipeline

If your logs are in JSON format, Datadog will parse all fields automatically and you can skip directly to the remapper and status remapper processors. If your logs are in key-value or a custom text format, you will need a Grok parser.

Navigate to **Logs > Configuration > Pipelines** in the Datadog UI and create a new pipeline with the filter `service:mft`.

### Processor 1: Grok Parser (for key-value format logs)

Add a Grok Parser processor to extract fields from your log lines. In the Datadog Grok parser, each line is one rule. The parser tries each rule in order and uses the first match.

For the success log format:

```
timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} size_mb=%{integer:size_mb} status=%{word:transfer_status} duration_s=%{number:duration_s} source_host=%{notSpace:source_host} destination_host=%{notSpace:destination_host}
```

For the failure log format (no size or duration fields):

```
timestamp=%{date("yyyy-MM-dd'T'HH:mm:ss'Z'"):transfer_timestamp} file=%{notSpace:file_name} status=%{word:transfer_status} error="%{data:error_message}" source_host=%{notSpace:source_host} destination_host=%{notSpace:destination_host}
```

Add both rules in the same Grok parser processor, one per line.

### Processor 2: Date Remapper

Add a Date Remapper to tell Datadog to use your parsed timestamp as the official log timestamp rather than the ingestion time. Set the source attribute to `transfer_timestamp`.

### Processor 3: Status Remapper

Add a Status Remapper and point it at the `transfer_status` attribute. This maps your SUCCESS and FAILED values to Datadog log status levels, which enables status-based filtering and coloring in the log explorer.

Since Datadog's standard statuses are `info`, `warn`, `error`, etc., you may want to add a Category Processor before the Status Remapper to convert your values:

- If `transfer_status` matches `SUCCESS`, set a new attribute `log_status` to `info`
- If `transfer_status` matches `FAILED`, set `log_status` to `error`

Then point the Status Remapper at `log_status`.

**Reference:** [Log Pipeline and Parsing](https://docs.datadoghq.com/logs/log_configuration/parsing/)

---

## Step 5: Create Log-Based Metrics

Log-based metrics allow you to generate time-series metrics from your parsed log data without storing every log event forever. This is the most efficient way to track KPIs like transfer counts, success rates, and duration trends over time.

Navigate to **Logs > Generate Metrics** in the Datadog UI.

For each metric below, click "Add a new metric" and configure as shown.

### Metric: mft.files.count

This counts every transfer attempt.

```
Filter:  service:mft
Name:    mft.files.count
Type:    count
Group by: source_host, destination_host
```

### Metric: mft.success.count

```
Filter:  service:mft @transfer_status:SUCCESS
Name:    mft.success.count
Type:    count
Group by: source_host, destination_host
```

### Metric: mft.failure.count

```
Filter:  service:mft @transfer_status:FAILED
Name:    mft.failure.count
Type:    count
Group by: source_host, destination_host
```

### Metric: mft.file.size

This captures the distribution of file sizes so you can track average, p95, and max.

```
Filter:  service:mft @transfer_status:SUCCESS
Name:    mft.file.size
Type:    distribution
Field:   @size_mb
Group by: source_host, destination_host
```

### Metric: mft.transfer.duration

```
Filter:  service:mft @transfer_status:SUCCESS
Name:    mft.transfer.duration
Type:    distribution
Field:   @duration_s
Group by: source_host, destination_host
```

> **Note:** The `@` prefix in filter queries refers to log attributes (parsed fields). Fields without `@` such as `service:mft` are log facets or reserved attributes.

**Reference:** [Log-Based Metrics](https://docs.datadoghq.com/logs/logs_to_metrics/)

---

## Step 6: Build a Monitoring Dashboard

Navigate to **Dashboards > New Dashboard** and create a new dashboard named something like "MFT Transfer Health". Below are the widgets you should include along with the queries that power them.

### Widget: Total Files Transferred (Timeseries)

Shows transfer volume over time, useful for spotting trends and peak windows.

```
sum:mft.files.count{*}.as_count()
```

Group by `source_host` to break down by server.

### Widget: Transfer Success Rate (Query Value)

Displays the percentage of successful transfers over the selected time window.

```
( sum:mft.success.count{*}.as_count() / sum:mft.files.count{*}.as_count() ) * 100
```

Set a conditional format to turn this red below 95 and green above 99.

### Widget: Transfer Failures (Timeseries or Top List)

```
sum:mft.failure.count{*}.as_count()
```

Set the y-axis to start at 0. Any bar above zero warrants investigation.

### Widget: Average Transfer Duration (Timeseries)

```
avg:mft.transfer.duration{*}
```

Add a p95 line on the same widget to catch outliers:

```
p95:mft.transfer.duration{*}
```

### Widget: File Size Distribution (Distribution)

```
avg:mft.file.size{*}
```

### Widget: Peak Transfer Windows (Heatmap or Timeseries with hourly rollup)

```
sum:mft.files.count{*}.rollup(sum, 3600)
```

This rolls up transfer counts into hourly buckets so you can visually identify when transfers are most active.

### Widget: Failure Log Stream

Add a Log Stream widget filtered to `service:mft @transfer_status:FAILED` so that the on-call engineer can see recent failure details without leaving the dashboard.

**Reference:** [Dashboards](https://docs.datadoghq.com/dashboards/)

---

## Step 7: Configure Monitors and Alerts

Monitoring without alerting is passive. The monitors below cover the three most important failure scenarios: active failures, stale transfers, and performance degradation.

Navigate to **Monitors > New Monitor > Metric** for metric-based monitors, or **Monitors > New Monitor > Log** for log-based monitors.

### Monitor 1: Transfer Failure Detected

This fires the moment any transfer failure is recorded. Given the critical nature of MFT in most environments, a zero-tolerance threshold is appropriate.

```
Monitor type: Metric Alert
Query:        sum(last_5m):sum:mft.failure.count{*}.as_count() > 0
Alert:        > 0
Notify:       @pagerduty-mft-oncall @slack-mft-alerts
Title:        [MFT] Transfer failure detected on {{source_host.name}}
Message:      One or more file transfer failures have been recorded in the last 5 minutes.
              Check the MFT dashboard and log explorer for details.
              Affected host: {{source_host.name}}
```

### Monitor 2: No Transfers Detected (Dead Man's Switch)

This fires when transfer activity drops to zero during a window when transfers should be occurring. You may want to scope the evaluation time window to align with your scheduled transfer intervals.

```
Monitor type: Metric Alert
Query:        sum(last_30m):sum:mft.files.count{*}.as_count() < 1
Alert:        < 1
Notify:       @slack-mft-alerts
Title:        [MFT] No transfers detected in the last 30 minutes
Message:      No file transfer events have been logged in the last 30 minutes.
              This may indicate the MFT process has stopped or log collection is broken.
```

For this monitor, if your transfers only run during business hours, use the monitor scheduling option to limit evaluation to those time windows and avoid false alerts during off-hours.

### Monitor 3: Transfer Duration Anomaly

This fires when average transfer duration exceeds a defined SLA threshold. Adjust the threshold to match what is acceptable for your workloads.

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

**Reference:** [Monitors](https://docs.datadoghq.com/monitors/)

---

## Step 8: Windows Event Log Collection (Optional)

Many enterprise MFT tools write events to the Windows Application Event Log in addition to or instead of file-based logs. If your MFT software uses Windows Event Log, configure the Datadog Agent to collect from the relevant event channel.

Open or create the following configuration file:

```
C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml
```

Add the following configuration:

```yaml
logs:
  - type: windows_event
    channel_path: Application
    source: windows.events
    service: mft
    log_processing_rules:
      - type: include_at_match
        name: include_mft_events
        pattern: "MOVEit|Axway|GoAnywhere|FileTransfer|MFT"
```

Replace the pattern values with the provider name or keywords that your specific MFT tool uses when writing to the Application log. You can find the exact provider name by opening Event Viewer on the Windows server and inspecting a transfer-related event entry under the "Source" column.

If your MFT tool writes to a custom event channel, replace `Application` with the channel path. You can find this in Event Viewer under "Applications and Services Logs".

```yaml
logs:
  - type: windows_event
    channel_path: MOVEit Transfer
    source: moveit
    service: mft
```

Restart the Agent after making this change:

```powershell
Restart-Service datadogagent
```

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
- The Datadog Agent service account does not have read access to the log file or directory
- `logs_enabled: true` is missing or commented out in `datadog.yaml`
- The log file is currently empty (the Agent will not report errors for empty files)

To grant the Datadog Agent service account read access to your log directory:

```powershell
$acl = Get-Acl "C:\MFT\logs"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT SERVICE\datadogagent", "Read", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\MFT\logs" $acl
```

### Grok parser is not extracting fields

Use the Grok debugger in the Datadog UI to test your parser rules. Navigate to **Logs > Configuration > Pipelines**, open your pipeline, and click on the Grok parser processor. Paste a sample raw log line into the debugger and check which fields are being extracted.

If no fields are extracted, check that your Grok rule pattern matches the exact format of your log line, including whitespace and special characters.

### Log-based metrics show no data

After creating a log-based metric, it only generates data from new incoming logs, not historical ones. Wait for new transfers to occur and verify logs are arriving in the Log Explorer before troubleshooting the metric.

Also confirm that the filter in your metric definition uses the correct syntax. For parsed attributes, prefix the attribute name with `@`. For example, `@transfer_status:SUCCESS` rather than `transfer_status:SUCCESS`.

### Timestamps are showing ingestion time instead of transfer time

This means the Date Remapper processor is either missing or pointing at the wrong attribute name. Double-check that the attribute name in the Date Remapper matches exactly what the Grok parser is outputting, including case sensitivity.

---

## Best Practices

**Use structured logs.** Whether you choose JSON or key-value pairs, the more consistent your log format is, the more reliable your parsing and metrics will be. Avoid free-form text log entries for transfer events.

**Every transfer event should log a status field.** Without an explicit status field in every log entry, you cannot reliably generate success and failure metrics. Make sure your MFT tool or script always writes a status regardless of whether the transfer succeeded or failed.

**Include file size and duration in every successful transfer log.** These fields are required for the performance metrics and are easy to include but easy to omit if not explicitly designed into the logging.

**Use consistent tagging.** Apply `service:mft` to all MFT log sources, and use additional tags like `source_host`, `destination_host`, and `env` to make your dashboards and alerts filterable. Consistent tagging is what allows you to scale this setup to many servers without rebuilding your dashboards.

**Set up the dead man's switch monitor.** The failure detection monitor catches active problems, but the "no transfers detected" monitor catches situations where everything looks fine but nothing is actually running. Both monitors are needed for complete coverage.

**Test your alert routing before you need it.** Send a test notification through each monitor to confirm that your PagerDuty, Slack, or email integration is working correctly.

---

## Summary

The table below maps each monitoring capability to the Datadog feature that powers it.

| Capability | Datadog Feature |
|---|---|
| Collecting transfer events | Logs Agent on Windows |
| Parsing log fields | Log Pipeline with Grok Parser |
| Tracking KPIs over time | Log-Based Metrics |
| Visualizing transfer health | Dashboards |
| Alerting on failures | Metric Monitors |
| Alerting on missed transfers | Metric Monitor (below threshold) |
| Raw log investigation | Log Explorer |

This approach requires no application code changes, no APM instrumentation, and no custom exporters. The Datadog Agent reads the log files your MFT software already produces, and the pipeline and metrics layer turns those logs into actionable observability.

---

## Reference Links

- [Datadog Agent on Windows](https://docs.datadoghq.com/agent/basic_agent_usage/windows/)
- [Log Collection on Windows](https://docs.datadoghq.com/logs/log_collection/windows/)
- [Log Pipeline and Parsing](https://docs.datadoghq.com/logs/log_configuration/parsing/)
- [Log-Based Metrics](https://docs.datadoghq.com/logs/logs_to_metrics/)
- [Dashboards](https://docs.datadoghq.com/dashboards/)
- [Monitors](https://docs.datadoghq.com/monitors/)
- [Windows Event Log Integration](https://docs.datadoghq.com/integrations/windows_event_log/)
- [Log Processing Rules](https://docs.datadoghq.com/agent/logs/advanced_log_collection/)

