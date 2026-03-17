# Importing Non-Standard AWS Metrics into Datadog

## Overview

The Datadog AWS integration automatically polls a defined set of CloudWatch
namespaces. Several AWS services, however, publish operational data in ways the
standard integration does not cover: some use CloudWatch namespaces not included
by default, others emit events through EventBridge without creating CloudWatch
metrics, and some require direct API polling to retrieve current state.

This guide covers all configuration steps and code required to bring the
following metrics into Datadog.

> **Prerequisites:** Before following this guide, complete all steps in the
> [Prerequisites README](https://github.com/rborkoto/partner-guides/blob/main/AWS%20Non%20Standard%20Metrics/Pre-requsities.md).

---

## Metric Source Reference

| Metric | AWS Source | Collection Method |
|---|---|---|
| `aws.drs.replication_lag` | CloudWatch `AWS/DRS` | Custom namespace |
| `aws.drs.recovery_point_age` | CloudWatch `AWS/DRS` | Custom namespace |
| `aws.drs.recovery_instance_ready` | DRS EventBridge events | Lambda and API |
| `aws.backup.backupjobfailed` | Backup EventBridge events | Lambda and API |
| `custom.drs.test.failures` | DRS API | Scheduled Lambda |
| `aws.config.rule.non_compliant` | Config EventBridge events | Lambda and API |
| `aws.config.public_resource_detected` | Config EventBridge events | Lambda and API |
| `aws.cloudtrail.unauthorized_api_calls` | CloudTrail Logs | Metric filter or Forwarder |
| `aws.cloudtrail.root_activity` | CloudTrail Logs | Metric filter or Forwarder |
| `aws.organizations.scp.denied_requests` | CloudTrail Logs (management account) | Metric filter or Forwarder |
| `aws.controltower.landingzone.health` | Control Tower EventBridge | Lambda and API |
| `aws.controltower.account.drift` | Control Tower EventBridge | Lambda and API |
| `aws.controltower.guardrail.failed` | Control Tower EventBridge or Security Hub | Lambda and API or Security Hub |
| `aws.controltower.account.provisioning_failed` | Service Catalog EventBridge | Lambda and API |
| `aws.controltower.logging.disabled` | Config EventBridge events | Lambda and API or Security Hub |
| `aws.ssm.managed_instance.online` | SSM API | Scheduled Lambda |
| `aws.ssm.patch.compliance` | SSM API | Scheduled Lambda |
| `aws.ssm.command.failed` | SSM EventBridge events | Lambda and API |
| `aws.ssm.automation.failed` | SSM EventBridge events | Lambda and API |
| `aws.ssm.session.failed` | CloudTrail EventBridge events | Lambda and API |

---

## Choosing Your Approach

Not all metrics require the same implementation path. Use the table below to
decide which sections of this guide apply to your setup before proceeding.

| Scenario | Recommended Path |
|---|---|
| Minimal setup, already forwarding logs to Datadog | Parts 1, 3, 4, and Alternative Option A |
| Security and compliance focus, using Security Hub | Parts 1, 3, 4, and Alternative Option B |
| Full metric control, no existing log forwarding | Parts 1, 2, 3, and 4 |
| Mixed environment | Combine namespace addition for DRS, Forwarder for log-derived metrics, Lambda only for polling and event-driven metrics |

The table below maps each metric to which part of this guide covers it.

| Metric | Covered In |
|---|---|
| `aws.drs.replication_lag` | Part 1 |
| `aws.drs.recovery_point_age` | Part 1 |
| `aws.cloudtrail.unauthorized_api_calls` | Part 2 or Alternative Option A |
| `aws.cloudtrail.root_activity` | Part 2 or Alternative Option A |
| `aws.organizations.scp.denied_requests` | Part 2 or Alternative Option A |
| `aws.backup.backupjobfailed` | Part 3 |
| `aws.config.rule.non_compliant` | Part 3 or Alternative Option B |
| `aws.config.public_resource_detected` | Part 3 or Alternative Option B |
| `aws.drs.recovery_instance_ready` | Part 3 |
| `aws.controltower.landingzone.health` | Part 3 |
| `aws.controltower.account.drift` | Part 3 |
| `aws.controltower.guardrail.failed` | Part 3 or Alternative Option B |
| `aws.controltower.account.provisioning_failed` | Part 3 |
| `aws.controltower.logging.disabled` | Part 3 or Alternative Option B |
| `aws.ssm.command.failed` | Part 3 |
| `aws.ssm.automation.failed` | Part 3 |
| `aws.ssm.session.failed` | Part 3 |
| `aws.ssm.managed_instance.online` | Part 4 |
| `aws.ssm.patch.compliance` | Part 4 |
| `custom.drs.test.failures` | Part 4 |

---

## Part 1: Custom CloudWatch Namespaces

AWS Elastic Disaster Recovery publishes replication and recovery metrics to the
`AWS/DRS` CloudWatch namespace. This namespace is not polled by the Datadog
integration by default and must be added manually.

**Metrics covered:**
- `aws.drs.replication_lag`
- `aws.drs.recovery_point_age`

**Steps:**

1. In Datadog go to **Integrations > Amazon Web Services**
2. Select the AWS account you are configuring
3. Open the **Metric Collection** tab
4. Scroll to the custom namespace section and add `AWS/DRS`
5. Save the configuration

| CloudWatch Metric | Datadog Metric | Dimension Tag |
|---|---|---|
| `ReplicationLag` | `aws.drs.replication_lag` | `sourceserverid` |
| `RecoveryPointAge` | `aws.drs.recovery_point_age` | `sourceserverid` |

DRS publishes metrics at one-minute resolution when replication is active.
Allow up to 15 minutes after saving before data appears in Datadog.

---

## Part 2: CloudWatch Logs Metric Filters

CloudTrail logs can be filtered to create CloudWatch custom metrics. Datadog
then polls those metrics by adding the custom namespace to the integration.

**Metrics covered:**
- `aws.cloudtrail.unauthorized_api_calls`
- `aws.cloudtrail.root_activity`
- `aws.organizations.scp.denied_requests`

> **Alternative:** If you are already forwarding logs to Datadog, skip this
> part and use **Alternative Option A** instead. It achieves the same result
> without CloudWatch metric filter configuration.

### 2.1 Confirm CloudTrail Log Delivery

Confirm your trail is delivering logs to a CloudWatch Logs log group. For SCP
events, use the trail on the management account.

```bash
aws cloudtrail describe-trails --include-shadow-trails false
```

### 2.2 Create the Metric Filters

Replace `YOUR_LOG_GROUP` with your CloudTrail log group name.

**Unauthorized API calls:**

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "UnauthorizedAPICalls" \
  --filter-pattern '{ ($.errorCode = "UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
    metricName="UnauthorizedAPICalls",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

**Root account activity:**

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "RootAccountActivity" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName="RootAccountActivity",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

**SCP denied requests:**

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "SCPDeniedRequests" \
  --filter-pattern '{ ($.errorCode = "AccessDenied") && ($.errorMessage = "*service control policy*") }' \
  --metric-transformations \
    metricName="SCPDeniedRequests",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

### 2.3 Add the Namespace to Datadog

Follow the same process as Part 1 and add `CloudTrailMetrics` as a custom
namespace in the Datadog AWS integration. Use the **Metric Renaming** feature
to map the CloudWatch-generated names to your target metric names.

---

## Part 3: EventBridge Lambda Integration

For services that emit events through EventBridge rather than CloudWatch, the
pattern is: EventBridge rule matches the event, triggers a Lambda function, and
the Lambda submits a metric to Datadog via the metrics API.

### 3.1 Lambda Function

All event-driven metrics share a single Lambda function. Create a file named
`lambda_function.py` with the following code.

```python
import json
import os
import time
import boto3
import urllib.request
from datetime import datetime, timedelta, timezone


# ── Metric Submission ──────────────────────────────────────────────────────────

def get_api_key():
    secret_arn = os.environ["DD_API_KEY_SECRET_ARN"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    return response["SecretString"]


def submit_metric(metric_name, value, tags, metric_type="count"):
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
    with urllib.request.urlopen(req) as resp:
        if resp.status not in (200, 202):
            raise RuntimeError(f"Datadog API returned {resp.status}")


# ── Event Router ───────────────────────────────────────────────────────────────

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

    if source == "aws.backup":
        handle_backup(detail, base_tags)
    elif source == "aws.config":
        handle_config(detail_type, detail, base_tags)
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
    elif source == "aws.events":
        run_pollers()


# ── AWS Backup ─────────────────────────────────────────────────────────────────

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


# ── AWS Config ─────────────────────────────────────────────────────────────────

PUBLIC_RESOURCE_RULES = [
    "s3-bucket-public-read-prohibited",
    "s3-bucket-public-write-prohibited",
    "restricted-ssh",
    "vpc-default-security-group-closed",
    "vpc-sg-open-only-to-authorized-ports",
]

CT_LOGGING_RULES = [
    "aws-controltower-cloudtrail",
    "aws-controltower-log",
]


def handle_config(detail_type, detail, base_tags):
    if detail_type != "Config Rules Compliance Change":
        return

    rule_name = detail.get("configRuleName", "unknown")
    resource_type = detail.get("resourceType", "unknown")
    resource_id = detail.get("resourceId", "unknown")
    compliance_type = detail.get(
        "newEvaluationResult", {}
    ).get("complianceType", "unknown")

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

    if any(r in rule_name.lower() for r in CT_LOGGING_RULES):
        submit_metric("aws.controltower.logging.disabled", 1, tags, "count")


# ── AWS DRS ────────────────────────────────────────────────────────────────────

def handle_drs(detail, base_tags):
    source_server_id = detail.get("sourceServerID", "unknown")
    readiness_state = detail.get("readinessState", "unknown")

    is_ready = 1 if readiness_state == "READY_FOR_RECOVERY" else 0
    tags = base_tags + [
        f"source_server_id:{source_server_id}",
        f"readiness_state:{readiness_state.lower()}",
    ]
    submit_metric("aws.drs.recovery_instance_ready", is_ready, tags, "gauge")


# ── AWS Control Tower ──────────────────────────────────────────────────────────

def handle_control_tower(detail_type, detail, base_tags):
    if "Drift" in detail_type:
        account_id = detail.get("accountId", "unknown")
        drift_type = detail.get("driftType", "unknown")
        tags = base_tags + [
            f"affected_account:{account_id}",
            f"drift_type:{drift_type.lower()}",
        ]
        submit_metric("aws.controltower.account.drift", 1, tags, "count")

    elif "Guardrail" in detail_type or "guardrail" in detail_type.lower():
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
        submit_metric(
            "aws.controltower.landingzone.health", is_healthy, tags, "gauge"
        )


# ── Service Catalog (Control Tower Account Provisioning) ──────────────────────

def handle_service_catalog(detail, base_tags):
    event_name = detail.get("eventName", "unknown")
    error_code = detail.get("errorCode", None)

    if error_code and event_name in ("ProvisionProduct", "UpdateProvisionedProduct"):
        tags = base_tags + [
            f"event_name:{event_name.lower()}",
            f"error_code:{error_code.lower()}",
        ]
        submit_metric(
            "aws.controltower.account.provisioning_failed", 1, tags, "count"
        )


# ── AWS SSM ────────────────────────────────────────────────────────────────────

FAILED_STATUSES = {"Failed", "TimedOut", "Cancelling", "Cancelled"}


def handle_ssm(detail_type, detail, base_tags):
    if detail_type == "EC2 Command Status-change Notification":
        status = detail.get("status", "unknown")
        if status in FAILED_STATUSES:
            tags = base_tags + [
                f"command_id:{detail.get('command-id', 'unknown')}",
                f"instance_id:{detail.get('instance-id', 'unknown')}",
                f"document_name:{detail.get('document-name', 'unknown')}",
                f"status:{status.lower()}",
            ]
            submit_metric("aws.ssm.command.failed", 1, tags, "count")

    elif detail_type in (
        "EC2 Automation Execution Status-change Notification",
        "EC2 Automation Step Status-change Notification",
    ):
        status = detail.get("Status", "unknown")
        if status in FAILED_STATUSES:
            tags = base_tags + [
                f"execution_id:{detail.get('ExecutionId', 'unknown')}",
                f"document_name:{detail.get('DocumentName', 'unknown')}",
                f"status:{status.lower()}",
            ]
            submit_metric("aws.ssm.automation.failed", 1, tags, "count")


# ── CloudTrail (SSM Session Failures) ─────────────────────────────────────────

def handle_cloudtrail(detail, base_tags):
    event_source = detail.get("eventSource", "")
    event_name = detail.get("eventName", "")
    error_code = detail.get("errorCode", None)

    if (
        event_source == "ssm.amazonaws.com"
        and event_name == "StartSession"
        and error_code
    ):
        user_arn = detail.get("userIdentity", {}).get("arn", "unknown")
        tags = base_tags + [
            f"error_code:{error_code.lower()}",
            f"user_arn:{user_arn}",
        ]
        submit_metric("aws.ssm.session.failed", 1, tags, "count")


# ── Pollers ────────────────────────────────────────────────────────────────────

def run_pollers():
    report_managed_instance_status()
    report_patch_compliance()
    report_drs_test_failures()


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
            submit_metric(
                "aws.ssm.managed_instance.online", is_online, tags, "gauge"
            )


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


def report_drs_test_failures():
    drs = boto3.client("drs")
    paginator = drs.get_paginator("describe_jobs")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    for page in paginator.paginate():
        for job in page.get("items", []):
            if job.get("initiatedBy", "") not in ("START_DRILL", "DRILL"):
                continue

            creation_time = job.get("creationDateTime")
            if creation_time and creation_time < cutoff:
                continue

            status = job.get("status", "")
            if status in ("COMPLETED_WITH_ERRORS", "FAILED"):
                tags = [
                    f"job_id:{job.get('jobID', 'unknown')}",
                    f"status:{status.lower()}",
                ]
                submit_metric("custom.drs.test.failures", 1, tags, "count")
```

### 3.2 EventBridge Rules

Create one rule per service. The pattern below is repeated for each rule.
Replace the rule name, event pattern, and statement ID each time.

```bash
# Create the rule
aws events put-rule \
  --name "RULE_NAME" \
  --event-pattern 'EVENT_PATTERN_JSON' \
  --state ENABLED

# Add Lambda as the target
aws events put-targets \
  --rule "RULE_NAME" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:datadog-aws-event-metrics"
  }]'

# Grant EventBridge permission to invoke the Lambda
aws lambda add-permission \
  --function-name datadog-aws-event-metrics \
  --statement-id "UNIQUE_STATEMENT_ID" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/RULE_NAME
```

Use the following event patterns for each rule.

**AWS Backup:**

```json
{
  "source": ["aws.backup"],
  "detail-type": ["Backup Job State Change"],
  "detail": { "state": ["FAILED", "ABORTED", "EXPIRED"] }
}
```

**AWS Config:**

```json
{
  "source": ["aws.config"],
  "detail-type": ["Config Rules Compliance Change"],
  "detail": {
    "newEvaluationResult": { "complianceType": ["NON_COMPLIANT"] }
  }
}
```

**AWS DRS:**

```json
{
  "source": ["aws.drs"]
}
```

**AWS Control Tower:**

```json
{
  "source": ["aws.controltower"]
}
```

**Service Catalog (Control Tower account provisioning):**

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

**SSM:**

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

**SSM Session Failures (via CloudTrail):**

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

> **Note for Control Tower:** Control Tower events originate in the management
> account. Deploy the Lambda and EventBridge rules there, or configure
> cross-account EventBridge event routing to forward `aws.controltower` events
> to the account where the Lambda runs.

---

## Part 4: Scheduled Lambda for Polling-Based Metrics

Three metrics require periodic API polling. These are handled by the
`run_pollers()` function already included in the Lambda above.

**Metrics covered:**
- `aws.ssm.managed_instance.online`
- `aws.ssm.patch.compliance`
- `custom.drs.test.failures`

Create a scheduled EventBridge rule to trigger the same Lambda on a fixed
interval. The `source: aws.events` value in the event routes to `run_pollers()`
inside the function.

```bash
aws events put-rule \
  --name "datadog-metrics-poller" \
  --schedule-expression "rate(5 minutes)" \
  --state ENABLED

aws events put-targets \
  --rule "datadog-metrics-poller" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:datadog-aws-event-metrics"
  }]'

aws lambda add-permission \
  --function-name datadog-aws-event-metrics \
  --statement-id "allow-scheduler" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/datadog-metrics-poller
```

Add the following permissions to the Lambda IAM role to allow API polling:

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

---

## Part 5: Lambda Deployment

### 5.1 IAM Role

Create the Lambda execution role with the following trust policy and attach
the required permissions.

```bash
aws iam create-role \
  --role-name datadog-metrics-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name datadog-metrics-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy \
  --role-name datadog-metrics-lambda-role \
  --policy-name datadog-metrics-permissions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:secretsmanager:*:*:secret:datadog/api-key*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ssm:DescribeInstanceInformation",
          "ssm:ListComplianceItems",
          "drs:DescribeJobs"
        ],
        "Resource": "*"
      }
    ]
  }'
```

### 5.2 Package and Deploy

```bash
zip metrics_lambda.zip lambda_function.py

aws lambda create-function \
  --function-name datadog-aws-event-metrics \
  --runtime python3.12 \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::ACCOUNT_ID:role/datadog-metrics-lambda-role \
  --zip-file fileb://metrics_lambda.zip \
  --timeout 60 \
  --memory-size 256 \
  --environment Variables="{
    DD_API_KEY_SECRET_ARN=arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:datadog/api-key,
    DD_SITE=datadoghq.com
  }"
```

---

## Part 6: Alternative Approaches

For some of the metrics in this guide there are simpler options that reduce
the amount of infrastructure and custom code required. Neither option replaces
the full guide but each can cover a meaningful subset of the metrics.

### Option A: Datadog Forwarder and Log-based Metrics

The [Datadog Forwarder](https://docs.datadoghq.com/logs/guide/forwarder/) is a
Datadog-maintained Lambda deployable from the AWS Serverless Application
Repository in a single CloudFormation stack. Once deployed and subscribed to
your CloudTrail log group, all log events flow directly into Datadog.

You then create **Log-based Metrics** in the Datadog UI under
**Logs > Generate Metrics** using filter queries, with no CloudWatch metric
filter setup or custom namespace configuration required.

This replaces Part 2 entirely for the following metrics:

| Metric | Datadog Log Filter Query |
|---|---|
| `aws.cloudtrail.unauthorized_api_calls` | `source:cloudtrail @errorCode:(UnauthorizedOperation OR AccessDenied*)` |
| `aws.cloudtrail.root_activity` | `source:cloudtrail @userIdentity.type:Root` |
| `aws.organizations.scp.denied_requests` | `source:cloudtrail @errorCode:AccessDenied @errorMessage:*service\ control\ policy*` |
| `aws.ssm.session.failed` | `source:cloudtrail @eventSource:ssm.amazonaws.com @eventName:StartSession @errorCode:*` |
| `aws.controltower.*` | `source:cloudtrail @eventSource:controltower.amazonaws.com` |

**Tradeoff:** Log ingestion into Datadog has its own cost implications
depending on volume. Review the cost considerations section before choosing
this path.

### Option B: AWS Security Hub and Datadog Integration

[AWS Security Hub](https://docs.datadoghq.com/integrations/amazon_security_hub/)
aggregates findings from AWS Config, Control Tower guardrails, GuardDuty, and
Inspector into a single service. The Datadog AWS integration can pull Security
Hub findings natively, removing the need for custom Lambda code for individual
compliance events.

This can partially replace the Config and Control Tower sections of Part 3.

| Metric | Security Hub Coverage |
|---|---|
| `aws.config.rule.non_compliant` | Config rule findings aggregated in Security Hub |
| `aws.config.public_resource_detected` | Config rules surfaced as Security Hub findings |
| `aws.controltower.guardrail.failed` | Control Tower compliance surfaced as findings |
| `aws.controltower.logging.disabled` | Config-backed rules surfaced as Security Hub findings |

**Tradeoff:** Security Hub findings are richer in context than raw numeric
metrics but are not identical to CloudWatch-style timeseries. Monitor
structures may need to be adapted to work with finding counts rather than
gauge values.

---

## Part 7: Verification

### Check Lambda Invocation Logs

```bash
aws logs tail /aws/lambda/datadog-aws-event-metrics --follow
```

### Send a Test Event

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

### Confirm Metrics in Datadog

Navigate to **Metrics > Explorer** and search for the metric name. Custom
metrics submitted via the API typically appear within two to three minutes.
CloudWatch namespace metrics added in Part 1 and Part 2 can take up to 15
minutes.

If a metric does not appear, check:

- Lambda CloudWatch Logs for errors in the function output
- That the Datadog API key in Secrets Manager is stored as plaintext and is valid
- That the EventBridge rule is in `ENABLED` state with the correct Lambda target ARN
- That the metric name in the Lambda code exactly matches what you are searching for

---

## Part 8: Recommended Monitors

Once data is flowing, the following monitors address the most operationally
critical signals. Create them under **Monitors > New Monitor > Metric** in
Datadog or define them using the
[Datadog Terraform provider](https://registry.terraform.io/providers/DataDog/datadog/latest).

| Monitor | Metric | Condition |
|---|---|---|
| DRS replication lag | `aws.drs.replication_lag` | Alert when value exceeds 300 seconds for any source server |
| Backup job failures | `aws.backup.backupjobfailed` | Alert when count is greater than zero over any 30-minute window |
| Config non-compliance | `aws.config.rule.non_compliant` | Alert on count increase above baseline over 15 minutes |
| Root account activity | `aws.cloudtrail.root_activity` | Alert immediately on any non-zero value |
| Control Tower guardrail failures | `aws.controltower.guardrail.failed` | Alert on any non-zero count |
| SCP denied requests | `aws.organizations.scp.denied_requests` | Alert on threshold breach indicating policy misconfiguration |
| SSM patch compliance drop | `aws.ssm.patch.compliance` | Alert when average drops below your compliance target |
| DRS test failures | `custom.drs.test.failures` | Alert on any non-zero count in a 24-hour window |

---

## Part 9: Additional Cost Considerations

The following areas can contribute to increased costs when implementing this
integration. No exact figures are provided as costs vary by account activity
and data volume.

### Datadog Custom Metrics
- Every metric submitted via the Datadog API counts as a custom metric against
  your Datadog quota
- High-cardinality tags such as `instance_id`, `resource_id`, and
  `execution_id` multiply the number of unique metric timeseries and are the
  most likely source of unexpected cost spikes
- Scheduled Lambda functions that report per-instance metrics (SSM patch
  compliance, managed instance status) can generate a large number of
  timeseries at scale

### AWS Lambda
- Event-driven Lambdas are low cost at normal alert volumes
- A spike in Config non-compliance events, SSM command failures, or Control
  Tower guardrail violations triggers a corresponding spike in Lambda
  invocations
- Scheduled Lambdas run continuously regardless of activity level

### AWS CloudWatch
- CloudWatch Logs metric filters are free to create but the custom metrics
  they publish are billed as CloudWatch custom metrics
- CloudTrail log ingestion and storage costs apply if not already accounted for

### AWS Secrets Manager
- Each Lambda invocation calls Secrets Manager to retrieve the Datadog API key
- At high invocation rates this adds up; consider caching the secret value
  within the Lambda execution context to reduce API calls

### AWS EventBridge
- Events processed on the default event bus from AWS services are free
- Cross-account event routing through a custom event bus incurs a per-event
  charge and should be reviewed if forwarding Control Tower events across
  many accounts

### Datadog Log Ingestion (Option A only)
- Forwarding CloudTrail logs to Datadog via the Forwarder increases log
  ingestion volume which is billed based on the Datadog log management plan
- Apply log exclusion filters in the Forwarder configuration to limit ingestion
  to only the event types needed for the metrics defined in this guideAdd to Conversation
