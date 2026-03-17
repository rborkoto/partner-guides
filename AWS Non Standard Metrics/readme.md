# Importing Non-Standard AWS Metrics into Datadog

## Table of Contents

- [Overview](#overview)
- [Important Notes](#important-notes)
- [Prerequisites](#prerequisites)
- [Quick Reference Table](#quick-reference-table)
- [Method 1: Custom CloudWatch Namespaces](#method-1-custom-cloudwatch-namespaces)
- [Method 2: CloudWatch Logs Metric Filters](#method-2-cloudwatch-logs-metric-filters)
- [Method 3: EventBridge, Lambda, and Datadog API](#method-3-eventbridge-lambda-and-datadog-api)
- [Method 4: Scheduled Lambda Polling](#method-4-scheduled-lambda-polling)
- [Lambda Deployment](#lambda-deployment)
- [GPU Metrics](#gpu-metrics)
- [Verification](#verification)
- [Recommended Monitors](#recommended-monitors)
- [References](#references)

---

## Overview

The Datadog AWS integration polls a predefined set of CloudWatch namespaces and collects metrics automatically. A number of AWS services publish their operational data in ways the standard integration does not cover:

- Some services publish to CloudWatch namespaces not included in Datadog's default polling list
- Some services emit data as EventBridge events and never create CloudWatch metrics
- Some services require direct API polling to retrieve current state

This guide covers four collection patterns to bring all metrics in the reference table below into Datadog. Each section includes configuration steps, AWS CLI commands, and Python Lambda code where applicable.

---

## Important Notes

**Custom metric quota.** All metrics collected using the methods in this guide count as custom metrics in Datadog, including those collected from custom CloudWatch namespaces. Custom metrics are billable. Review the [Datadog custom metrics documentation](https://docs.datadoghq.com/metrics/custom_metrics/) before implementing at scale.

**Metric naming via API.** Metrics submitted directly through the Datadog metrics API use the exact name specified in your code. Metrics collected through CloudWatch custom namespace polling follow Datadog's CloudWatch naming normalisation and the resulting name in Datadog may not match the target name exactly. Use the metric renaming feature in the Datadog AWS integration, or use the Lambda and API approach, if exact naming is required.

**Event schema verification.** EventBridge event schemas for services such as AWS Control Tower can vary between service versions. Before deploying Lambda handlers to production, confirm the actual event structure emitted in your environment using EventBridge Schema Discovery or by reviewing events in the AWS console. Field names in handler code should be treated as a starting point, not a guarantee.

---

## Prerequisites

- Datadog AWS integration configured with a valid IAM cross-account role. See [AWS Integration Setup](https://docs.datadoghq.com/integrations/amazon_web_services/).
- AWS CloudTrail enabled with a trail delivering logs to a CloudWatch Logs log group.
- IAM permissions to create CloudWatch metric filters, EventBridge rules, Lambda functions, and IAM roles.
- A Datadog API key stored as a plaintext secret string in AWS Secrets Manager.
- Python 3.12 for Lambda functions in this guide.
- AWS CLI configured with appropriate credentials.

---

## Quick Reference Table

| Metric | AWS Data Source | Collection Method | Section |
|---|---|---|---|
| `aws.drs.replication_lag` | CloudWatch `AWS/DRS` namespace | Custom CloudWatch namespace | [Method 1](#method-1-custom-cloudwatch-namespaces) |
| `aws.drs.recovery_point_age` | CloudWatch `AWS/DRS` namespace | Custom CloudWatch namespace | [Method 1](#method-1-custom-cloudwatch-namespaces) |
| `aws.drs.recovery_instance_ready` | DRS EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.backup.backupjobfailed` | AWS Backup EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `custom.drs.test.failures` | DRS `DescribeJobs` API | Scheduled Lambda + Datadog API | [Method 4](#method-4-scheduled-lambda-polling) |
| `aws.config.rule.non_compliant` | AWS Config EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.config.public_resource_detected` | AWS Config EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.cloudtrail.unauthorized_api_calls` | CloudTrail logs via CloudWatch Logs | CloudWatch Logs metric filter | [Method 2](#method-2-cloudwatch-logs-metric-filters) |
| `aws.cloudtrail.root_activity` | CloudTrail logs via CloudWatch Logs | CloudWatch Logs metric filter | [Method 2](#method-2-cloudwatch-logs-metric-filters) |
| `aws.organizations.scp.denied_requests` | CloudTrail logs (management account) | CloudWatch Logs metric filter | [Method 2](#method-2-cloudwatch-logs-metric-filters) |
| `aws.controltower.landingzone.health` | Control Tower EventBridge (management account) | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.controltower.account.drift` | Control Tower EventBridge (management account) | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.controltower.guardrail.failed` | Control Tower EventBridge (management account) | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.controltower.account.provisioning_failed` | Service Catalog EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.controltower.logging.disabled` | AWS Config EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.ssm.managed_instance.online` | SSM `DescribeInstanceInformation` API | Scheduled Lambda + Datadog API | [Method 4](#method-4-scheduled-lambda-polling) |
| `aws.ssm.patch.compliance` | SSM `ListComplianceItems` API | Scheduled Lambda + Datadog API | [Method 4](#method-4-scheduled-lambda-polling) |
| `aws.ssm.command.failed` | SSM EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.ssm.automation.failed` | SSM EventBridge events | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| `aws.ssm.session.failed` | CloudTrail events via EventBridge | EventBridge + Lambda + Datadog API | [Method 3](#method-3-eventbridge-lambda-and-datadog-api) |
| GPU Metrics | Windows or Linux agent | DCGM Exporter or built-in GPU monitoring | [GPU Metrics](#gpu-metrics) |

---

## Method 1: Custom CloudWatch Namespaces

AWS Elastic Disaster Recovery publishes replication and recovery metrics to the CloudWatch namespace `AWS/DRS`. This namespace is not included in Datadog's default integration polling list and must be added manually.

For the full list of available metrics and dimensions published by DRS, see the [AWS DRS monitoring with CloudWatch documentation](https://docs.aws.amazon.com/drs/latest/userguide/monitoring-cloudwatch.html).

**Metrics covered:**
- `aws.drs.replication_lag`
- `aws.drs.recovery_point_age`

### Configuration Steps

1. In Datadog, go to **Integrations > Amazon Web Services**.
2. Select the AWS account to configure.
3. Open the **Metric Collection** tab.
4. Scroll to the custom namespaces section and add `AWS/DRS`.
5. Save the configuration.

Datadog will poll the following metrics from the `AWS/DRS` namespace:

| CloudWatch Metric Name | Datadog Metric Name | Primary Dimension |
|---|---|---|
| `ReplicationLag` | `aws.drs.replication_lag` | `SourceServerID` |
| `RecoveryPointAge` | `aws.drs.recovery_point_age` | `SourceServerID` |

CloudWatch dimensions are converted to Datadog tags automatically. The `SourceServerID` dimension becomes the tag `sourceserverid` on each data point, which lets you scope monitors and dashboards to individual source servers.

Allow up to 15 minutes after saving before data appears in Datadog. DRS publishes these metrics at one-minute resolution when replication is active. If no data appears, confirm that at least one DRS source server has an active replication session.

---

## Method 2: CloudWatch Logs Metric Filters

CloudTrail records every API call made in your AWS account. When CloudTrail is configured to deliver logs to a CloudWatch Logs log group, metric filters extract numeric counts from matching log events and publish them as CloudWatch custom metrics. Datadog can then collect those metrics by polling the custom namespace.

See the [CloudWatch Logs metric filter documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html) and the [filter pattern syntax reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for background on how filters work.

**Metrics covered:**
- `aws.cloudtrail.unauthorized_api_calls`
- `aws.cloudtrail.root_activity`
- `aws.organizations.scp.denied_requests`

### Step 1: Confirm CloudTrail Log Delivery

In the AWS console, go to **CloudTrail > Trails** and confirm that your trail has a CloudWatch Logs log group associated with it.

For SCP-related events (`aws.organizations.scp.denied_requests`), the trail must be on the **management account**. SCP deny actions originate at the management account before affecting member accounts. See the [AWS Organizations SCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) for details.

Note the log group name before running the commands below.

### Step 2: Create Metric Filters

Replace `YOUR_LOG_GROUP` with your CloudTrail log group name in each command.

**Unauthorized API calls** counts events where the error code indicates an authorisation failure:

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "UnauthorizedAPICalls" \
  --filter-pattern '{ ($.errorCode = "UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
    metricName="UnauthorizedAPICalls",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

**Root account activity** counts events where the calling identity is the root user:

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "RootAccountActivity" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName="RootAccountActivity",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

**SCP denied requests** counts access denied errors that reference a service control policy in the error message. SCP denials appear in CloudTrail logs as `AccessDenied` errors. See the [CloudTrail log event reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html) for the log structure:

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "SCPDeniedRequests" \
  --filter-pattern '{ ($.errorCode = "AccessDenied") && ($.errorMessage = "*service control policy*") }' \
  --metric-transformations \
    metricName="SCPDeniedRequests",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

> **Note:** The exact wording in `errorMessage` for SCP denials can vary. Verify the phrase used in your environment by querying recent CloudTrail events in CloudWatch Logs Insights before relying on this filter in production monitors.

### Step 3: Add CloudTrailMetrics Namespace to Datadog

Follow the same process as Method 1 and add `CloudTrailMetrics` as a custom namespace in the Datadog AWS integration. Datadog will normalise the CloudWatch metric names when ingesting them. Confirm the resulting names in **Metrics > Explorer** after the namespace is added. Use metric renaming in the integration configuration if the names need to match the target names exactly.

---

## Method 3: EventBridge, Lambda, and Datadog API

For services that publish events through EventBridge rather than writing CloudWatch metrics, the collection pattern is:

1. An EventBridge rule matches events from the target service.
2. The rule invokes a Lambda function.
3. The Lambda parses the event and calls the [Datadog metrics submission API](https://docs.datadoghq.com/api/latest/metrics/).

See the [Amazon EventBridge rules documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html) for background on how EventBridge rules and targets work.

### IAM Role for Lambda

Create an IAM execution role for the Lambda function with the following inline policy. For the polling-based handlers in Method 4, add the relevant read permissions for the SSM and DRS APIs to this same role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Sid": "SecretsManagerReadAPIKey",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:datadog/api-key*"
    }
  ]
}
```

### Base Lambda Function

The function below is the shared foundation for all event-based metric handlers. Individual service handlers are added in each section below and registered in `route_event`. The function uses only `boto3` and the Python standard library, both of which are available in the Lambda Python 3.12 runtime. No additional packages need to be installed or packaged.

**Environment variables required:**

| Variable | Value |
|---|---|
| `DD_API_KEY_SECRET_ARN` | ARN of the Secrets Manager secret containing the Datadog API key |
| `DD_SITE` | Your Datadog site, e.g. `datadoghq.com` or `datadoghq.eu` |

```python
import json
import os
import time
import urllib.request
import boto3


def get_api_key():
    """Retrieve the Datadog API key from Secrets Manager."""
    secret_arn = os.environ["DD_API_KEY_SECRET_ARN"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    return response["SecretString"]


def submit_metric(metric_name, value, tags, metric_type="count"):
    """
    Submit a single metric to Datadog via the v1 series API.

    metric_type accepts: "count", "gauge", or "rate"
    Reference: https://docs.datadoghq.com/api/latest/metrics/#submit-metrics
    """
    api_key = get_api_key()
    site = os.environ.get("DD_SITE", "datadoghq.com")
    url = f"https://api.{site}/api/v1/series"

    payload = json.dumps({
        "series": [{
            "metric": metric_name,
            "points": [[int(time.time()), float(value)]],
            "type": metric_type,
            "tags": tags
        }]
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "DD-API-KEY": api_key
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status not in (200, 202):
            raise RuntimeError(f"Datadog API returned HTTP {resp.status}")


def lambda_handler(event, context):
    source = event.get("source", "")
    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})
    region = event.get("region", "unknown")
    account = event.get("account", "unknown")

    base_tags = [
        f"region:{region}",
        f"account_id:{account}",
    ]

    route_event(source, detail_type, detail, base_tags)


def route_event(source, detail_type, detail, base_tags):
    if source == "aws.backup":
        handle_backup(detail, base_tags)
    elif source == "aws.config":
        handle_config(detail, base_tags)
    elif source == "aws.drs":
        handle_drs(detail, base_tags)
    elif source == "aws.controltower":
        handle_control_tower(detail_type, detail, base_tags)
    elif source == "aws.servicecatalog":
        handle_service_catalog(detail, base_tags)
    elif source == "aws.ssm":
        handle_ssm(detail_type, detail, base_tags)
    elif source == "aws.cloudtrail":
        handle_cloudtrail(detail, base_tags)
```

---

### 3.1 AWS Backup

AWS Backup publishes a `Backup Job State Change` event to EventBridge whenever a backup job transitions state. See the [AWS Backup EventBridge notifications documentation](https://docs.aws.amazon.com/aws-backup/latest/devguide/eventbridge.html) for the full event schema and available states.

**EventBridge rule pattern:**

```json
{
  "source": ["aws.backup"],
  "detail-type": ["Backup Job State Change"],
  "detail": {
    "state": ["FAILED", "ABORTED", "EXPIRED"]
  }
}
```

**Handler:**

```python
def handle_backup(detail, base_tags):
    state = detail.get("state", "unknown")
    resource_type = detail.get("resourceType", "unknown")
    vault_name = detail.get("backupVaultName", "unknown")

    if state in ("FAILED", "ABORTED", "EXPIRED"):
        tags = base_tags + [
            f"resource_type:{resource_type.lower()}",
            f"backup_vault:{vault_name}",
            f"state:{state.lower()}",
        ]
        submit_metric("aws.backup.backupjobfailed", 1, tags, "count")
```

---

### 3.2 AWS Config

AWS Config publishes a `Config Rules Compliance Change` event to EventBridge each time a rule evaluation result changes. See the [AWS Config EventBridge documentation](https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html) for the full event schema.

The same EventBridge rule and handler cover three metrics:
- `aws.config.rule.non_compliant` fires on every non-compliant evaluation
- `aws.config.public_resource_detected` fires only when a rule from a configurable list is violated
- `aws.controltower.logging.disabled` fires when a Control Tower logging-related Config rule is violated

**EventBridge rule pattern:**

```json
{
  "source": ["aws.config"],
  "detail-type": ["Config Rules Compliance Change"],
  "detail": {
    "newEvaluationResult": {
      "complianceType": ["NON_COMPLIANT"]
    }
  }
}
```

**Handler:**

```python
# Update this list to match the AWS Config rules in your environment
# that detect publicly exposed resources.
PUBLIC_RESOURCE_RULES = [
    "s3-bucket-public-read-prohibited",
    "s3-bucket-public-write-prohibited",
    "restricted-ssh",
    "vpc-default-security-group-closed",
    "vpc-sg-open-only-to-authorized-ports",
]

# Control Tower deploys Config rules with names prefixed aws-controltower-.
# Update these keywords to match the logging-related rules in your landing zone.
CT_LOGGING_RULE_KEYWORDS = [
    "aws-controltower-cloudtrail",
    "aws-controltower-log",
]

def handle_config(detail, base_tags):
    rule_name = detail.get("configRuleName", "unknown")
    resource_type = detail.get("resourceType", "unknown")
    resource_id = detail.get("resourceId", "unknown")
    compliance_type = (
        detail.get("newEvaluationResult", {}).get("complianceType", "unknown")
    )

    if compliance_type != "NON_COMPLIANT":
        return

    tags = base_tags + [
        f"config_rule:{rule_name}",
        f"resource_type:{resource_type.lower()}",
        f"resource_id:{resource_id}",
    ]

    submit_metric("aws.config.rule.non_compliant", 1, tags, "count")

    if any(r in rule_name.lower() for r in PUBLIC_RESOURCE_RULES):
        submit_metric("aws.config.public_resource_detected", 1, tags, "count")

    if any(kw in rule_name.lower() for kw in CT_LOGGING_RULE_KEYWORDS):
        submit_metric("aws.controltower.logging.disabled", 1, tags, "count")
```

---

### 3.3 AWS DRS Recovery Instance Readiness

AWS DRS emits events to EventBridge when recovery instance state changes occur. See the [AWS DRS monitoring documentation](https://docs.aws.amazon.com/drs/latest/userguide/monitoring-cloudwatch.html) for background on DRS monitoring.

This metric uses a gauge: `1` when the instance is ready for recovery, `0` when it is not.

> **Important:** Verify the exact `detail-type` string and field names emitted by DRS in your environment before deploying to production. Use EventBridge Schema Discovery or inspect live events in the AWS console to confirm the structure.

**EventBridge rule pattern:**

```json
{
  "source": ["aws.drs"]
}
```

**Handler:**

```python
def handle_drs(detail, base_tags):
    source_server_id = detail.get("sourceServerID", "unknown")
    readiness_state = detail.get("readinessState", "unknown")

    is_ready = 1 if readiness_state == "READY_FOR_RECOVERY" else 0

    tags = base_tags + [
        f"source_server_id:{source_server_id}",
        f"readiness_state:{readiness_state.lower()}",
    ]
    submit_metric("aws.drs.recovery_instance_ready", is_ready, tags, "gauge")
```

---

### 3.4 AWS Control Tower

Control Tower publishes lifecycle events to EventBridge from the management account. These events cover landing zone health, account drift, guardrail compliance, and account provisioning. See the [Control Tower lifecycle events documentation](https://docs.aws.amazon.com/controltower/latest/userguide/lifecycle-events.html) for the documented event schemas.

> **Important:** Control Tower events originate exclusively in the management account. If this Lambda is deployed in a member account, configure cross-account EventBridge event bus forwarding from the management account, or deploy a separate instance of the Lambda in the management account.

> **Important:** Control Tower's event schema has evolved across service versions. The field names below reflect documented lifecycle event structures, but they must be verified against events in your specific environment before being used in production.

**EventBridge rule pattern:**

```json
{
  "source": ["aws.controltower"]
}
```

**Handler:**

```python
def handle_control_tower(detail_type, detail, base_tags):
    if "Drift" in detail_type:
        account_id = detail.get("accountId", "unknown")
        drift_type = detail.get("driftType", "unknown")
        tags = base_tags + [
            f"affected_account:{account_id}",
            f"drift_type:{drift_type.lower()}",
        ]
        submit_metric("aws.controltower.account.drift", 1, tags, "count")

    elif "Guardrail" in detail_type:
        guardrail_id = detail.get("guardrailId", "unknown")
        compliance_status = detail.get("complianceStatus", "unknown")
        account_id = detail.get("accountId", "unknown")
        tags = base_tags + [
            f"guardrail_id:{guardrail_id}",
            f"affected_account:{account_id}",
            f"compliance_status:{compliance_status.lower()}",
        ]
        if compliance_status != "COMPLIANT":
            submit_metric("aws.controltower.guardrail.failed", 1, tags, "count")

    elif "Landing Zone" in detail_type:
        health_status = detail.get("healthStatus", "unknown")
        is_healthy = 1 if health_status == "HEALTHY" else 0
        tags = base_tags + [f"health_status:{health_status.lower()}"]
        submit_metric("aws.controltower.landingzone.health", is_healthy, tags, "gauge")
```

**Account provisioning failures** are surfaced through AWS Service Catalog, which Control Tower uses internally to provision accounts. Add a second EventBridge rule targeting Service Catalog events:

```json
{
  "source": ["aws.servicecatalog"],
  "detail-type": ["AWS Service Event via CloudTrail"],
  "detail": {
    "eventName": ["ProvisionProduct", "UpdateProvisionedProduct"],
    "errorCode": [{ "exists": true }]
  }
}
```

**Handler:**

```python
def handle_service_catalog(detail, base_tags):
    event_name = detail.get("eventName", "unknown")
    error_code = detail.get("errorCode", None)

    if error_code and event_name in ("ProvisionProduct", "UpdateProvisionedProduct"):
        tags = base_tags + [
            f"event_name:{event_name.lower()}",
            f"error_code:{error_code.lower()}",
        ]
        submit_metric("aws.controltower.account.provisioning_failed", 1, tags, "count")
```

---

### 3.5 AWS Systems Manager

SSM publishes Run Command and Automation execution state changes to EventBridge. See the [Systems Manager EventBridge events documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-eventbridge-events.html) for the full list of event types and field schemas.

**EventBridge rule pattern for command and automation events:**

```json
{
  "source": ["aws.ssm"],
  "detail-type": [
    "EC2 Command Status-change Notification",
    "EC2 Automation Execution Status-change Notification",
    "EC2 Automation Step Status-change Notification"
  ]
}
```

**Handler:**

```python
FAILED_STATUSES = {"Failed", "TimedOut", "Cancelling", "Cancelled"}

def handle_ssm(detail_type, detail, base_tags):
    if detail_type == "EC2 Command Status-change Notification":
        command_id = detail.get("command-id", "unknown")
        status = detail.get("status", "unknown")
        instance_id = detail.get("instance-id", "unknown")
        document_name = detail.get("document-name", "unknown")

        if status in FAILED_STATUSES:
            tags = base_tags + [
                f"command_id:{command_id}",
                f"instance_id:{instance_id}",
                f"document_name:{document_name}",
                f"status:{status.lower()}",
            ]
            submit_metric("aws.ssm.command.failed", 1, tags, "count")

    elif detail_type in (
        "EC2 Automation Execution Status-change Notification",
        "EC2 Automation Step Status-change Notification",
    ):
        execution_id = detail.get("ExecutionId", "unknown")
        status = detail.get("Status", "unknown")
        document_name = detail.get("DocumentName", "unknown")

        if status in FAILED_STATUSES:
            tags = base_tags + [
                f"execution_id:{execution_id}",
                f"document_name:{document_name}",
                f"status:{status.lower()}",
            ]
            submit_metric("aws.ssm.automation.failed", 1, tags, "count")
```

**Session Manager failures** are recorded in CloudTrail when a `StartSession` API call fails with an error. Add a second EventBridge rule targeting CloudTrail events from the SSM service:

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ssm.amazonaws.com"],
    "eventName": ["StartSession"],
    "errorCode": [{ "exists": true }]
  }
}
```

**Handler:**

```python
def handle_cloudtrail(detail, base_tags):
    event_source = detail.get("eventSource", "")
    event_name = detail.get("eventName", "")
    error_code = detail.get("errorCode", None)

    if (
        event_source == "ssm.amazonaws.com"
        and event_name == "StartSession"
        and error_code
    ):
        user_identity = detail.get("userIdentity", {})
        user_arn = user_identity.get("arn", "unknown")
        tags = base_tags + [
            f"error_code:{error_code.lower()}",
            f"user_arn:{user_arn}",
        ]
        submit_metric("aws.ssm.session.failed", 1, tags, "count")
```

---

## Method 4: Scheduled Lambda Polling

Three metrics represent ongoing state rather than discrete events and require periodic API polling. A separate Lambda function is triggered on a schedule by an EventBridge rule.

**Create the scheduled rule:**

```bash
aws events put-rule \
  --name "datadog-metrics-poller" \
  --schedule-expression "rate(5 minutes)" \
  --state ENABLED
```

**Add polling permissions to the Lambda IAM role:**

```json
{
  "Effect": "Allow",
  "Action": [
    "ssm:DescribeInstanceInformation",
    "ssm:ListComplianceItems",
    "drs:DescribeJobs"
  ],
  "Resource": "*"
}
```

### 4.1 SSM Managed Instance Online Status

Calls `DescribeInstanceInformation` to report the connectivity status of each managed instance. See the [DescribeInstanceInformation API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html).

```python
def report_managed_instance_status():
    ssm = boto3.client("ssm")
    paginator = ssm.get_paginator("describe_instance_information")

    for page in paginator.paginate():
        for instance in page.get("InstanceInformationList", []):
            ping_status = instance.get("PingStatus", "Unknown")
            instance_id = instance.get("InstanceId", "unknown")
            platform_type = instance.get("PlatformType", "unknown")

            is_online = 1 if ping_status == "Online" else 0
            tags = [
                f"instance_id:{instance_id}",
                f"platform_type:{platform_type.lower()}",
                f"ping_status:{ping_status.lower()}",
            ]
            submit_metric("aws.ssm.managed_instance.online", is_online, tags, "gauge")
```

### 4.2 SSM Patch Compliance

Calls `ListComplianceItems` to retrieve patch compliance data across managed instances. See the [ListComplianceItems API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ListComplianceItems.html).

```python
def report_patch_compliance():
    ssm = boto3.client("ssm")
    paginator = ssm.get_paginator("list_compliance_items")

    for page in paginator.paginate(
        Filters=[{"Key": "ComplianceType", "Values": ["Patch"]}]
    ):
        for item in page.get("ComplianceItems", []):
            compliance_status = item.get("Status", "unknown")
            instance_id = item.get("ResourceId", "unknown")
            severity = item.get("Severity", "unknown")

            is_compliant = 1 if compliance_status == "COMPLIANT" else 0
            tags = [
                f"instance_id:{instance_id}",
                f"compliance_status:{compliance_status.lower()}",
                f"severity:{severity.lower()}",
            ]
            submit_metric("aws.ssm.patch.compliance", is_compliant, tags, "gauge")
```

### 4.3 Custom DRS Test Failures

Calls `DescribeJobs` to identify DRS drill jobs that failed or completed with errors in the last 24 hours. See the [DRS DescribeJobs API reference](https://docs.aws.amazon.com/drs/latest/APIReference/API_DescribeJobs.html).

```python
from datetime import datetime, timedelta, timezone

def report_drs_test_failures():
    drs = boto3.client("drs")
    paginator = drs.get_paginator("describe_jobs")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    for page in paginator.paginate():
        for job in page.get("items", []):
            initiated_by = job.get("initiatedBy", "")

            # Only process jobs initiated as drills
            if initiated_by not in ("START_DRILL", "DRILL"):
                continue

            creation_time = job.get("creationDateTime")
            if creation_time and creation_time < cutoff:
                continue

            status = job.get("status", "")
            job_id = job.get("jobID", "unknown")

            if status in ("COMPLETED_WITH_ERRORS", "FAILED"):
                tags = [
                    f"job_id:{job_id}",
                    f"status:{status.lower()}",
                    f"initiated_by:{initiated_by.lower()}",
                ]
                submit_metric("custom.drs.test.failures", 1, tags, "count")
```

**Lambda entry point for the polling function:**

```python
def lambda_handler(event, context):
    report_managed_instance_status()
    report_patch_compliance()
    report_drs_test_failures()
```

---

## Lambda Deployment

### Packaging

Both Lambda functions use only `boto3` and the Python standard library, which are available in the Lambda Python 3.12 runtime. No additional packages need to be installed. See the [Lambda deployment package documentation](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html) for background.

```bash
# Event-driven function
zip -r event_lambda.zip lambda_function.py

# Polling function
zip -r polling_lambda.zip polling_function.py
```

### Deploy the Lambda Functions

Replace `ACCOUNT_ID`, `REGION`, and the role ARN with your values.

```bash
# Event-driven Lambda
aws lambda create-function \
  --function-name datadog-aws-event-metrics \
  --runtime python3.12 \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::ACCOUNT_ID:role/datadog-metrics-lambda-role \
  --zip-file fileb://event_lambda.zip \
  --timeout 60 \
  --memory-size 256 \
  --environment Variables="{DD_API_KEY_SECRET_ARN=arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:datadog/api-key,DD_SITE=datadoghq.com}"

# Polling Lambda
aws lambda create-function \
  --function-name datadog-aws-polling-metrics \
  --runtime python3.12 \
  --handler polling_function.lambda_handler \
  --role arn:aws:iam::ACCOUNT_ID:role/datadog-metrics-lambda-role \
  --zip-file fileb://polling_lambda.zip \
  --timeout 120 \
  --memory-size 256 \
  --environment Variables="{DD_API_KEY_SECRET_ARN=arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:datadog/api-key,DD_SITE=datadoghq.com}"
```

### Create EventBridge Rules and Attach Lambda Targets

The following pattern applies to every EventBridge rule defined in Method 3. Repeat for each rule, substituting the rule name, event pattern, and a unique `statement-id`.

```bash
# Create the EventBridge rule
aws events put-rule \
  --name "datadog-backup-job-failures" \
  --event-pattern '{
    "source": ["aws.backup"],
    "detail-type": ["Backup Job State Change"],
    "detail": { "state": ["FAILED","ABORTED","EXPIRED"] }
  }' \
  --state ENABLED

# Add the Lambda as the rule target
aws events put-targets \
  --rule "datadog-backup-job-failures" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:datadog-aws-event-metrics"
  }]'

# Grant EventBridge permission to invoke the Lambda
aws lambda add-permission \
  --function-name datadog-aws-event-metrics \
  --statement-id "allow-backup-rule" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/datadog-backup-job-failures
```

### Attach the Polling Rule to the Polling Lambda

```bash
aws events put-targets \
  --rule "datadog-metrics-poller" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:datadog-aws-polling-metrics"
  }]'

aws lambda add-permission \
  --function-name datadog-aws-polling-metrics \
  --statement-id "allow-poller-rule" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/datadog-metrics-poller
```


---

## Verification

After deploying all Lambda functions and EventBridge rules, confirm that metrics are reaching Datadog before creating monitors against them.

**Tail Lambda execution logs:**

```bash
aws logs tail /aws/lambda/datadog-aws-event-metrics --follow
aws logs tail /aws/lambda/datadog-aws-polling-metrics --follow
```

A successful execution produces no errors. Authentication failures appear as `RuntimeError` messages referencing a Datadog API HTTP status code.

**Send a test event to the event-driven Lambda:**

```bash
aws lambda invoke \
  --function-name datadog-aws-event-metrics \
  --payload '{
    "source": "aws.backup",
    "detail-type": "Backup Job State Change",
    "detail": {
      "state": "FAILED",
      "resourceType": "EC2",
      "backupVaultName": "test-vault"
    },
    "region": "us-east-1",
    "account": "123456789012"
  }' \
  response.json && cat response.json
```

**Verify in Datadog:**

Go to **Metrics > Explorer** and search for the target metric name. Metrics submitted via the Datadog API typically appear within two to three minutes. CloudWatch custom namespace metrics (Methods 1 and 2) can take up to 15 minutes to appear after the namespace is first added.

If a metric does not appear after the expected window, check the following:

1. Lambda execution logs contain no errors.
2. The Datadog API key in Secrets Manager is valid and has not been rotated without updating the secret value.
3. The metric name in the Lambda code exactly matches what you are searching for in Datadog.
4. The CloudWatch namespace has been saved in the Datadog AWS integration configuration (Methods 1 and 2).
5. The EventBridge rule is in `ENABLED` state and the correct Lambda function ARN is set as the target.

---

## Recommended Monitors

Once data is flowing, the table below lists recommended starting thresholds for each metric. Create monitors under **Monitors > New Monitor > Metric** in Datadog, or define them as code using the [Datadog Terraform provider](https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor).

| Metric | Recommended Condition | Rationale |
|---|---|---|
| `aws.drs.replication_lag` | Alert when value exceeds 300 seconds for any source server | Breach indicates RPO is at risk |
| `aws.drs.recovery_point_age` | Alert when approaching defined RTO/RPO targets | Direct RPO breach indicator per source server |
| `aws.drs.recovery_instance_ready` | Alert when gauge value is 0 for any source server | Instance not ready means recovery drills will fail |
| `aws.backup.backupjobfailed` | Alert on any non-zero count in a 30-minute window | Backup failures require immediate investigation |
| `aws.config.rule.non_compliant` | Alert on count increase above rolling baseline | Tracks introduction of new compliance violations |
| `aws.config.public_resource_detected` | Alert on any non-zero count | Public resource exposure is a high-severity security finding |
| `aws.cloudtrail.unauthorized_api_calls` | Alert using anomaly detection on rolling baseline | A spike may indicate reconnaissance activity or misconfigured permissions |
| `aws.cloudtrail.root_activity` | Alert on any non-zero count | Root account activity should never occur in normal operations |
| `aws.organizations.scp.denied_requests` | Alert on count spike above baseline | May indicate a misconfigured SCP or an unauthorised action attempt |
| `aws.controltower.guardrail.failed` | Alert on any non-zero count | Guardrail failures represent governance violations |
| `aws.controltower.account.drift` | Alert on any non-zero count | Drift means Control Tower has lost governance of that account's configuration |
| `aws.controltower.logging.disabled` | Alert on any non-zero count | Loss of centralised logging is a compliance and security risk |
| `aws.ssm.managed_instance.online` | Alert when gauge drops to 0 for any instance for more than one polling interval | Instance has lost connectivity to SSM |
| `aws.ssm.patch.compliance` | Alert when average drops below agreed target, e.g. 90% | Tracks patch coverage across the managed fleet |
| `aws.ssm.command.failed` | Alert when count exceeds expected baseline | Unexpected failures may indicate connectivity or permission issues |
| `custom.drs.test.failures` | Alert on any non-zero count | Drill failures must be investigated before a real recovery event |

---

## References

### AWS Documentation

| Resource | URL |
|---|---|
| AWS DRS Monitoring with CloudWatch | https://docs.aws.amazon.com/drs/latest/userguide/monitoring-cloudwatch.html |
| AWS DRS DescribeJobs API | https://docs.aws.amazon.com/drs/latest/APIReference/API_DescribeJobs.html |
| AWS Backup EventBridge Notifications | https://docs.aws.amazon.com/aws-backup/latest/devguide/eventbridge.html |
| AWS Config EventBridge Integration | https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html |
| CloudWatch Logs Metric Filters | https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html |
| CloudWatch Logs Filter Pattern Syntax | https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html |
| AWS CloudTrail Log Event Reference | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html |
| AWS Control Tower Lifecycle Events | https://docs.aws.amazon.com/controltower/latest/userguide/lifecycle-events.html |
| AWS Organizations Service Control Policies | https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html |
| AWS Systems Manager EventBridge Events | https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-eventbridge-events.html |
| SSM DescribeInstanceInformation API | https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html |
| SSM ListComplianceItems API | https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ListComplianceItems.html |
| Amazon EventBridge Rules | https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html |
| AWS Lambda Deployment Packages | https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html |
| AWS Secrets Manager | https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html |

### Datadog Documentation

| Resource | URL |
|---|---|
| Datadog AWS Integration | https://docs.datadoghq.com/integrations/amazon_web_services/ |
| Datadog Metrics Submission API | https://docs.datadoghq.com/api/latest/metrics/ |
| Datadog Custom Metrics | https://docs.datadoghq.com/metrics/custom_metrics/ |
| Datadog Monitor Creation | https://docs.datadoghq.com/monitors/create/ |
| Datadog NVIDIA DCGM Integration | https://docs.datadoghq.com/integrations/nvidia_dcgm/ |
| Datadog Terraform Provider — Monitor Resource | https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor |
