# Importing Non-Standard AWS Metrics into Datadog

## Overview

The Datadog AWS integration automatically polls a defined set of CloudWatch
namespaces. Several AWS services, however, publish operational data in ways
the standard integration does not cover: some use CloudWatch namespaces not
included by default, others emit events through EventBridge without creating
CloudWatch metrics, and some require direct API polling to retrieve current
state.

This guide presents the recommended approach for each metric first, favouring
the lowest-effort option. Custom Lambda code is only introduced where no
simpler path exists.

> **Prerequisites:** Before following this guide, complete all steps in the
> [Prerequisites README](./PREREQUISITES.md).

---

## Metric Source Reference

| Metric | AWS Source | Recommended Method |
|---|---|---|
| `aws.drs.replication_lag` | CloudWatch `AWS/DRS` | Custom namespace |
| `aws.drs.recovery_point_age` | CloudWatch `AWS/DRS` | Custom namespace |
| `aws.drs.recovery_instance_ready` | DRS EventBridge events | Lambda and API |
| `aws.backup.backupjobfailed` | Backup EventBridge events | Lambda and API |
| `custom.drs.test.failures` | DRS API | Scheduled Lambda |
| `aws.config.rule.non_compliant` | Config via Security Hub | Security Hub integration |
| `aws.config.public_resource_detected` | Config via Security Hub | Security Hub integration |
| `aws.cloudtrail.unauthorized_api_calls` | CloudTrail Logs | Forwarder and log-based metric |
| `aws.cloudtrail.root_activity` | CloudTrail Logs | Forwarder and log-based metric |
| `aws.organizations.scp.denied_requests` | CloudTrail Logs (management account) | Forwarder and log-based metric |
| `aws.controltower.landingzone.health` | Control Tower EventBridge | Lambda and API |
| `aws.controltower.account.drift` | Control Tower EventBridge | Lambda and API |
| `aws.controltower.guardrail.failed` | Control Tower via Security Hub | Security Hub integration |
| `aws.controltower.account.provisioning_failed` | Service Catalog EventBridge | Lambda and API |
| `aws.controltower.logging.disabled` | Config via Security Hub | Security Hub integration |
| `aws.ssm.managed_instance.online` | SSM API | Scheduled Lambda |
| `aws.ssm.patch.compliance` | SSM API | Scheduled Lambda |
| `aws.ssm.command.failed` | SSM EventBridge events | Lambda and API |
| `aws.ssm.automation.failed` | SSM EventBridge events | Lambda and API |
| `aws.ssm.session.failed` | CloudTrail Logs | Forwarder and log-based metric |

---

## Choosing Your Approach

Use this table to identify which parts of the guide apply before proceeding.

| Metric Group | Recommended Path | Fallback Path |
|---|---|---|
| DRS namespace metrics | Part 1 only | Not applicable |
| CloudTrail log-derived metrics | Part 2 (Forwarder) | Part 2 Alternative (metric filters) |
| Config and Control Tower compliance | Part 3 (Security Hub) | Part 4 Lambda handlers |
| Backup, DRS events, CT provisioning, SSM events | Part 4 (Lambda) | Not applicable |
| SSM state and DRS test failures | Part 5 (Scheduled Lambda) | Not applicable |

| Metric | Covered In |
|---|---|
| `aws.drs.replication_lag` | Part 1 |
| `aws.drs.recovery_point_age` | Part 1 |
| `aws.cloudtrail.unauthorized_api_calls` | Part 2 |
| `aws.cloudtrail.root_activity` | Part 2 |
| `aws.organizations.scp.denied_requests` | Part 2 |
| `aws.ssm.session.failed` | Part 2 |
| `aws.config.rule.non_compliant` | Part 3 |
| `aws.config.public_resource_detected` | Part 3 |
| `aws.controltower.guardrail.failed` | Part 3 |
| `aws.controltower.logging.disabled` | Part 3 |
| `aws.backup.backupjobfailed` | Part 4 |
| `aws.drs.recovery_instance_ready` | Part 4 |
| `aws.controltower.landingzone.health` | Part 4 |
| `aws.controltower.account.drift` | Part 4 |
| `aws.controltower.account.provisioning_failed` | Part 4 |
| `aws.ssm.command.failed` | Part 4 |
| `aws.ssm.automation.failed` | Part 4 |
| `aws.ssm.managed_instance.online` | Part 5 |
| `aws.ssm.patch.compliance` | Part 5 |
| `custom.drs.test.failures` | Part 5 |

---

## Part 1: Custom CloudWatch Namespaces

AWS Elastic Disaster Recovery publishes replication and recovery metrics to
the `AWS/DRS` CloudWatch namespace. This namespace is not polled by the
Datadog integration by default and must be added manually. This is the
simplest configuration change in the guide and requires no code.

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

CloudWatch dimensions are automatically converted to Datadog tags. Allow up
to 15 minutes after saving before data appears in Datadog.

---

## Part 2: Datadog Forwarder and Log-based Metrics (Recommended)

The Datadog Forwarder is a Datadog-maintained Lambda function that forwards
CloudWatch Logs directly into Datadog. Deploying it requires a single
CloudFormation stack from the AWS Serverless Application Repository. Once your
CloudTrail log group is subscribed to the Forwarder, you create metrics
entirely within the Datadog UI using log filter queries, with no CloudWatch
metric filter configuration or custom namespace setup required.

**Metrics covered:**
- `aws.cloudtrail.unauthorized_api_calls`
- `aws.cloudtrail.root_activity`
- `aws.organizations.scp.denied_requests`
- `aws.ssm.session.failed`

### 2.1 Deploy the Datadog Forwarder

Deploy the Forwarder from the AWS Serverless Application Repository. This
creates a CloudFormation stack containing the Lambda function and all required
IAM permissions.

```bash
aws cloudformation create-stack \
  --stack-name datadog-forwarder \
  --template-url https://datadog-cloudformation-template.s3.amazonaws.com/aws/forwarder/latest.yaml \
  --parameters \
    ParameterKey=DdApiKey,ParameterValue=YOUR_DATADOG_API_KEY \
    ParameterKey=DdSite,ParameterValue=datadoghq.com \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
```

Wait for the stack to reach `CREATE_COMPLETE` before proceeding.

```bash
aws cloudformation wait stack-create-complete \
  --stack-name datadog-forwarder
```

Retrieve the Forwarder Lambda ARN for use in the next step.

```bash
aws cloudformation describe-stacks \
  --stack-name datadog-forwarder \
  --query "Stacks[0].Outputs[?OutputKey=='DatadogForwarderArn'].OutputValue" \
  --output text
```

### 2.2 Subscribe the CloudTrail Log Group to the Forwarder

Replace `YOUR_LOG_GROUP` with your CloudTrail log group name and
`FORWARDER_ARN` with the ARN retrieved above.

```bash
aws lambda add-permission \
  --function-name FORWARDER_ARN \
  --statement-id cloudtrail-log-subscription \
  --action lambda:InvokeFunction \
  --principal logs.amazonaws.com \
  --source-arn arn:aws:logs:REGION:ACCOUNT_ID:log-group:YOUR_LOG_GROUP

aws logs put-subscription-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "datadog-forwarder" \
  --filter-pattern "" \
  --destination-arn FORWARDER_ARN
```

> **Note for SCP metrics:** The `aws.organizations.scp.denied_requests` metric
> relies on CloudTrail events that originate in the management account. Subscribe
> the management account CloudTrail log group to a Forwarder instance deployed
> in the management account.

### 2.3 Create Log-based Metrics in Datadog

Once logs are flowing into Datadog, create the metrics under
**Logs > Generate Metrics**. Select **New Metric** and use the following
filter queries and metric names.

| Metric Name | Filter Query | Type |
|---|---|---|
| `aws.cloudtrail.unauthorized_api_calls` | `source:cloudtrail @errorCode:(UnauthorizedOperation OR AccessDenied*)` | Count |
| `aws.cloudtrail.root_activity` | `source:cloudtrail @userIdentity.type:Root -@userIdentity.invokedBy:* @eventType:AwsApiCall` | Count |
| `aws.organizations.scp.denied_requests` | `source:cloudtrail @errorCode:AccessDenied @errorMessage:*service\ control\ policy*` | Count |
| `aws.ssm.session.failed` | `source:cloudtrail @eventSource:ssm.amazonaws.com @eventName:StartSession @errorCode:*` | Count |

For each metric, add the following fields as tags to preserve useful
dimensions for filtering and grouping in monitors:

- `@awsRegion`
- `@userIdentity.arn`
- `@errorCode`

### 2.4 Alternative: CloudWatch Logs Metric Filters

If you are not forwarding logs to Datadog and do not wish to deploy the
Forwarder, you can create CloudWatch metric filters directly on the CloudTrail
log group and then add the `CloudTrailMetrics` namespace to the Datadog
integration.

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

Add `CloudTrailMetrics` as a custom namespace in the Datadog AWS integration
following the same process as Part 1. Use the **Metric Renaming** feature to
map the CloudWatch-generated names to your target metric names.

---

## Part 3: AWS Security Hub Integration (Recommended)

AWS Security Hub aggregates compliance findings from Config rules, Control
Tower guardrails, and other security services into a single service. The
Datadog AWS integration can pull these findings natively, removing the need
for custom Lambda code for individual compliance events.

**Metrics covered:**
- `aws.config.rule.non_compliant`
- `aws.config.public_resource_detected`
- `aws.controltower.guardrail.failed`
- `aws.controltower.logging.disabled`

> **Important limitation:** Security Hub surfaces findings rather than
> continuous timeseries metrics. If your monitors require numeric gauge or
> count values over time, use the Lambda fallback in Part 4 instead for these
> metrics.

### 3.1 Enable AWS Security Hub

```bash
aws securityhub enable-security-hub \
  --enable-default-standards \
  --region YOUR_REGION
```

Enable the AWS Foundational Security Best Practices and CIS standards to
ensure Config and Control Tower rules surface as findings.

```bash
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    '[
      {"StandardsArn":"arn:aws:securityhub:REGION::standards/aws-foundational-security-best-practices/v/1.0.0"},
      {"StandardsArn":"arn:aws:securityhub:REGION::standards/cis-aws-foundations-benchmark/v/1.2.0"}
    ]'
```

### 3.2 Enable the AWS Config Integration in Security Hub

```bash
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:REGION::product/aws/config
```

### 3.3 Configure the Datadog Security Hub Integration

1. In Datadog go to **Integrations > Amazon Security Hub**
2. Select the AWS account and region
3. Enable the integration and save

Findings from Config rules and Control Tower guardrails will begin appearing
in Datadog under **Security > Findings**. You can create monitors on finding
counts using the query `source:aws_securityhub` in the Logs or Security
Signals explorer.

### 3.4 Alternative: EventBridge Lambda for Compliance Metrics

If Security Hub findings are not sufficient and you require numeric timeseries
metrics for the compliance signals above, use the Lambda handlers for Config
and Control Tower described in Part 4. The Lambda `handle_config` and
`handle_control_tower` functions submit these as count metrics directly to
Datadog.

---

## Part 4: EventBridge Lambda Integration

For services that emit events through EventBridge rather than CloudWatch or
logs, the approach is: EventBridge rule matches the event, triggers a Lambda
function, and the Lambda submits a metric to Datadog via the metrics API.

This part also includes the fallback handlers for Config and Control Tower
compliance metrics if you chose not to use Security Hub in Part 3.

### 4.1 Lambda Function

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
        # Only required if not using Security Hub (Part 3)
        handle_config(detail_type, detail, base_tags)
    elif source == "aws.drs":
        handle_drs(detail, base_tags)
    elif source == "aws.controltower":
        # Only required if not using Security Hub (Part 3)
        handle_control_tower(detail_type, detail, base_tags)
    elif source == "aws.servicecatalog":
        handle_service_catalog(detail, base_tags)
    elif source == "aws.ssm":
        handle_ssm(detail_type, detail, base_tags)
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


# ── AWS Config (fallback if not using Security Hub) ───────────────────────────

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


# ── AWS Control Tower (fallback if not using Security Hub) ────────────────────

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


# ── Pollers (Scheduled) ────────────────────────────────────────────────────────

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

### 4.2 EventBridge Rules

Create one rule per service using the pattern below. Replace the rule name,
event pattern, and statement ID for each.

```bash
aws events put-rule \
  --name "RULE_NAME" \
  --event-pattern 'EVENT_PATTERN_JSON' \
  --state ENABLED

aws events put-targets \
  --rule "RULE_NAME" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:datadog-aws-event-metrics"
  }]'

aws lambda add-permission \
  --function-name datadog-aws-event-metrics \
  --statement-id "UNIQUE_STATEMENT_ID" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/RULE_NAME
```

**AWS Backup:**

```json
{
  "source": ["aws.backup"],
  "detail-type": ["Backup Job State Change"],
  "detail": { "state": ["FAILED", "ABORTED", "EXPIRED"] }
}
```

**AWS Config (only required if not using Security Hub):**

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

**AWS Control Tower (only required if not using Security Hub):**

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

> **Note for Control Tower:** Control Tower events originate in the management
> account. Deploy the Lambda and EventBridge rules there, or configure
> cross-account EventBridge routing to forward events to the account where
> the Lambda runs.

---

## Part 5: Scheduled Lambda for Polling-Based Metrics

Three metrics require periodic API polling and have no simpler alternative.
These are handled by the `run_pollers()` function included in the Lambda above.

**Metrics covered:**
- `aws.ssm.managed_instance.online`
- `aws.ssm.patch.compliance`
- `custom.drs.test.failures`

Create a scheduled EventBridge rule to trigger the Lambda every five minutes.

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

---

## Part 6: Lambda Deployment

### 6.1 IAM Role

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

### 6.2 Package and Deploy

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

Navigate to **Metrics > Explorer** and search for the metric name. Metrics
submitted via the API typically appear within two to three minutes. CloudWatch
namespace metrics from Part 1 can take up to 15 minutes. Log-based metrics
from Part 2 appear as soon as logs begin flowing through the Forwarder.

If a metric does not appear after the expected window, check:

- Lambda CloudWatch Logs for errors
- That the Datadog API key in Secrets Manager is stored as a plaintext string
  and has not expired
- That the EventBridge rule is in `ENABLED` state with the correct Lambda ARN
  as the target
- For the Forwarder approach, that the log group subscription filter is active
  and the Forwarder Lambda is receiving invocations

---

## Part 8: Recommended Monitors

Once data is flowing, create monitors under **Monitors > New Monitor > Metric**
in Datadog or define them using the
[Datadog Terraform provider](https://registry.terraform.io/providers/DataDog/datadog/latest).

| Monitor | Metric | Recommended Condition |
|---|---|---|
| DRS replication lag | `aws.drs.replication_lag` | Alert when value exceeds 300 seconds for any source server |
| Backup job failures | `aws.backup.backupjobfailed` | Alert when count is greater than zero in any 30-minute window |
| Config non-compliance | `aws.config.rule.non_compliant` | Alert on count increase above baseline over 15 minutes |
| Root account activity | `aws.cloudtrail.root_activity` | Alert immediately on any non-zero value |
| Control Tower guardrail failures | `aws.controltower.guardrail.failed` | Alert on any non-zero count |
| SCP denied requests | `aws.organizations.scp.denied_requests` | Alert on threshold breach |
| SSM patch compliance drop | `aws.ssm.patch.compliance` | Alert when average drops below your compliance target |
| DRS test failures | `custom.drs.test.failures` | Alert on any non-zero count in a 24-hour window |

---

## Part 9: Additional Cost Considerations

The following areas can contribute to increased costs. No exact figures are
provided as costs vary by account activity and data volume.

### Datadog Custom Metrics
- Every metric submitted via the Datadog API counts against your Datadog
  custom metric quota
- High-cardinality tags such as `instance_id`, `resource_id`, and
  `execution_id` multiply the number of unique metric timeseries and are the
  most likely source of unexpected cost spikes
- Scheduled Lambdas reporting per-instance metrics (SSM patch compliance,
  managed instance status) can generate a large timeseries count at scale

### Datadog Log Ingestion (Part 2 Forwarder path)
- Forwarding CloudTrail logs via the Forwarder increases Datadog log ingestion
  volume, which is billed based on your log management plan
- Apply exclusion filters in the Forwarder configuration to limit ingestion to
  only the event types needed for the metrics defined in this guide

### AWS Lambda
- Event-driven Lambdas are low cost at normal alert volumes
- A spike in Config non-compliance events, SSM command failures, or Control
  Tower guardrail violations triggers a proportional spike in Lambda invocations
- Scheduled Lambdas run continuously regardless of activity level

### AWS CloudWatch
- CloudWatch Logs metric filters are free to create but the custom metrics
  they publish are billed as CloudWatch custom metrics
- CloudTrail log storage costs apply if not already accounted for in your
  baseline

### AWS Secrets Manager
- Each Lambda invocation calls Secrets Manager to retrieve the Datadog API key
- At high invocation rates this adds up; consider caching the secret value
  within the Lambda execution context to reduce API calls per invocation

### AWS EventBridge
- Events on the default bus from AWS services are free
- Cross-account routing through a custom event bus incurs a per-event charge
  and should be reviewed if forwarding Control Tower events across many accountsAdd to Conversation
