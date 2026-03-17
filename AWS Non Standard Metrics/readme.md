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
> [Prerequisites Guide](https://github.com/rborkoto/partner-guides/blob/main/AWS%20Non%20Standard%20Metrics/Pre-requsities.md).

---

## Multi-Account Setup Considerations

Several metrics in this guide require configuration in specific AWS accounts.

| Metric | Account Requirement | Notes |
|---|---|---|
| `aws.organizations.scp.denied_requests` | Management account | CloudTrail log group must be in management account |
| `aws.controltower.landingzone.health` | Management account | Control Tower events originate in management account |
| `aws.controltower.account.drift` | Management account | Control Tower events originate in management account |
| `aws.controltower.guardrail.failed` | Management account | Control Tower events and Security Hub findings originate in management account |
| `aws.controltower.account.provisioning_failed` | Management account | Service Catalog events for Control Tower are in management account |
| `aws.controltower.logging.disabled` | Management account | Control Tower managed Config rules are evaluated in management account |

**For multi-account deployments:**
- Deploy the Datadog Forwarder in the management account for SCP metrics (Part 2)
- Deploy Lambda functions and EventBridge rules in the management account for
  Control Tower metrics (Part 4)
- Configure cross-account EventBridge routing if you prefer to centralise
  Lambda execution in a single account
- Enable Security Hub in both management and member accounts if you need Config
  compliance metrics from member accounts

---

## Metric Source Reference

| Metric | AWS Source | Recommended Method |
|---|---|---|
| `aws.drs.replication_lag` | CloudWatch `AWS/DRS` | Part 1: CloudWatch Metric Streams |
| `aws.drs.recovery_point_age` | CloudWatch `AWS/DRS` | Part 1: CloudWatch Metric Streams |
| `aws.drs.recovery_instance_ready` | DRS EventBridge events | Part 4: Lambda and API |
| `aws.backup.backupjobfailed` | Backup EventBridge events | Part 4: Lambda and API |
| `custom.drs.test.failures` | DRS API | Part 5: Scheduled Lambda |
| `aws.config.rule.non_compliant` | Config EventBridge or Security Hub | Part 4: Lambda (alerting), Part 3: Security Hub (compliance reporting) |
| `aws.config.public_resource_detected` | Config EventBridge or Security Hub | Part 4: Lambda (alerting), Part 3: Security Hub (compliance reporting) |
| `aws.cloudtrail.unauthorized_api_calls` | CloudTrail Logs | Part 2: Forwarder and log-based metric |
| `aws.cloudtrail.root_activity` | CloudTrail Logs | Part 2: Forwarder and log-based metric |
| `aws.organizations.scp.denied_requests` | CloudTrail Logs (management account) | Part 2: Forwarder and log-based metric |
| `aws.controltower.landingzone.health` | Control Tower EventBridge | Part 4: Lambda and API |
| `aws.controltower.account.drift` | Control Tower EventBridge | Part 4: Lambda and API |
| `aws.controltower.guardrail.failed` | Control Tower EventBridge or Security Hub | Part 4: Lambda (alerting), Part 3: Security Hub (compliance reporting) |
| `aws.controltower.account.provisioning_failed` | Service Catalog EventBridge | Part 4: Lambda and API |
| `aws.controltower.logging.disabled` | Config EventBridge or Security Hub | Part 4: Lambda (alerting), Part 3: Security Hub (compliance reporting) |
| `aws.ssm.managed_instance.online` | SSM API | Part 5: Scheduled Lambda |
| `aws.ssm.patch.compliance` | SSM API | Part 5: Scheduled Lambda |
| `aws.ssm.command.failed` | SSM EventBridge events | Part 4: Lambda and API |
| `aws.ssm.automation.failed` | SSM EventBridge events | Part 4: Lambda and API |
| `aws.ssm.session.failed` | CloudTrail Logs | Part 2: Forwarder and log-based metric |

---

## Choosing Your Approach

Use this table to identify which parts of this guide apply to your setup
before proceeding.

| Metric Group | Recommended Path | Alternative Path |
|---|---|---|
| DRS CloudWatch namespace metrics | Part 1 (Metric Streams) | Part 1 Option B (Lambda polling) |
| CloudTrail log-derived metrics | Part 2 (Forwarder) | Part 2 Alternative (metric filters) |
| Config and Control Tower compliance metrics for alerting | Part 4 (Lambda) | Not applicable |
| Config and Control Tower compliance for reporting and investigation | Part 3 (Security Hub) | Not applicable |
| Backup, DRS events, CT provisioning, SSM events | Part 4 (Lambda) | Not applicable |
| SSM state and DRS test failures | Part 5 (Scheduled Lambda) | Not applicable |

| Metric | Primary Part | Also Covered In |
|---|---|---|
| `aws.drs.replication_lag` | Part 1 | |
| `aws.drs.recovery_point_age` | Part 1 | |
| `aws.cloudtrail.unauthorized_api_calls` | Part 2 | |
| `aws.cloudtrail.root_activity` | Part 2 | |
| `aws.organizations.scp.denied_requests` | Part 2 | |
| `aws.ssm.session.failed` | Part 2 | |
| `aws.config.rule.non_compliant` | Part 4 (alerting) | Part 3 (reporting) |
| `aws.config.public_resource_detected` | Part 4 (alerting) | Part 3 (reporting) |
| `aws.controltower.guardrail.failed` | Part 4 (alerting) | Part 3 (reporting) |
| `aws.controltower.logging.disabled` | Part 4 (alerting) | Part 3 (reporting) |
| `aws.backup.backupjobfailed` | Part 4 | |
| `aws.drs.recovery_instance_ready` | Part 4 | |
| `aws.controltower.landingzone.health` | Part 4 | |
| `aws.controltower.account.drift` | Part 4 | |
| `aws.controltower.account.provisioning_failed` | Part 4 | |
| `aws.ssm.command.failed` | Part 4 | |
| `aws.ssm.automation.failed` | Part 4 | |
| `aws.ssm.managed_instance.online` | Part 5 | |
| `aws.ssm.patch.compliance` | Part 5 | |
| `custom.drs.test.failures` | Part 5 | |

---

## Part 1: DRS CloudWatch Metrics

The `AWS/DRS` CloudWatch namespace is not in the Datadog integration predefined
namespace list and cannot be added through the Datadog UI directly. The
following options cover how to get these metrics into Datadog.

**Metrics covered:**
- `aws.drs.replication_lag`
- `aws.drs.recovery_point_age`

### Option A: CloudWatch Metric Streams (Recommended)

CloudWatch Metric Streams push metrics from any CloudWatch namespace,
including `AWS/DRS`, directly to Datadog via Kinesis Data Firehose. This
requires no custom code and covers any namespace automatically.

**Step 1: Create the required IAM roles**

Role for Kinesis Data Firehose to deliver to the Datadog endpoint:

```bash
aws iam create-role \
  --role-name FirehoseDatadogRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "firehose.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name FirehoseDatadogRole \
  --policy-name FirehoseDatadogPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetBucketLocation"],
      "Resource": [
        "arn:aws:s3:::YOUR_BACKUP_BUCKET",
        "arn:aws:s3:::YOUR_BACKUP_BUCKET/*"
      ]
    }]
  }'
```

Role for CloudWatch to write to the Firehose stream:

```bash
aws iam create-role \
  --role-name CloudWatchMetricStreamRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "streams.metrics.cloudwatch.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name CloudWatchMetricStreamRole \
  --policy-name CloudWatchMetricStreamPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ],
      "Resource": "arn:aws:firehose:REGION:ACCOUNT_ID:deliverystream/datadog-metrics-stream"
    }]
  }'
```

**Step 2: Create the Kinesis Data Firehose delivery stream**

```bash
aws firehose create-delivery-stream \
  --delivery-stream-name datadog-metrics-stream \
  --delivery-stream-type DirectPut \
  --http-endpoint-destination-configuration '{
    "EndpointConfiguration": {
      "Url": "https://awsmetrics-intake.datadoghq.com/v1/input",
      "Name": "Datadog",
      "AccessKey": "YOUR_DATADOG_API_KEY"
    },
    "RequestConfiguration": {
      "ContentEncoding": "GZIP"
    },
    "BufferingHints": {
      "SizeInMBs": 4,
      "IntervalInSeconds": 60
    },
    "S3BackupMode": "FailedDataOnly",
    "S3DestinationConfiguration": {
      "BucketARN": "arn:aws:s3:::YOUR_BACKUP_BUCKET",
      "RoleARN": "arn:aws:iam::ACCOUNT_ID:role/FirehoseDatadogRole"
    }
  }'
```

**Step 3: Create the CloudWatch Metric Stream**

```bash
aws cloudwatch put-metric-stream \
  --name datadog-drs-metric-stream \
  --firehose-arn arn:aws:firehose:REGION:ACCOUNT_ID:deliverystream/datadog-metrics-stream \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/CloudWatchMetricStreamRole \
  --output-format opentelemetry1.0 \
  --include-filters '[
    {"Namespace": "AWS/DRS"}
  ]'
```

> Remove `--include-filters` to stream all CloudWatch namespaces to Datadog.
> This is useful if you plan to expand metric collection to other services but
> will increase data volume and cost.

**Step 4: Confirm the stream is running**

```bash
aws cloudwatch get-metric-stream \
  --name datadog-drs-metric-stream \
  --query 'State'
```

The state should return `RUNNING`. DRS metrics will appear in Datadog within
a few minutes.

---

### Option B: Lambda Polling CloudWatch (Fallback)

If Metric Streams cannot be used in your environment, the Lambda in Part 4
includes a `poll_drs_cloudwatch_metrics()` function that polls CloudWatch for
DRS metrics on the same schedule as the other pollers.

This function is already included in the Lambda code in Part 4. To enable it:

1. Follow Part 4 and Part 6 to deploy the Lambda
2. Ensure the scheduled rule from Part 5 is active
3. Confirm the Lambda IAM role includes the following permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics",
    "drs:DescribeSourceServers"
  ],
  "Resource": "*"
}
```

These permissions are already included in the IAM policy defined in Part 6.

> If you are using Option A (Metric Streams), remove or comment out the
> `poll_drs_cloudwatch_metrics()` call inside `run_pollers()` in the Lambda
> to avoid duplicate metric submissions.

---

## Part 2: Datadog Forwarder and Log-based Metrics (Recommended)

The Datadog Forwarder is a Datadog-maintained Lambda function that forwards
CloudWatch Logs directly into Datadog. Deploying it requires a single
CloudFormation stack from the AWS Serverless Application Repository. Once your
CloudTrail log group is subscribed to the Forwarder, metrics are created
entirely within the Datadog UI using log filter queries with no CloudWatch
metric filter configuration or custom namespace setup required.

**Metrics covered:**
- `aws.cloudtrail.unauthorized_api_calls`
- `aws.cloudtrail.root_activity`
- `aws.organizations.scp.denied_requests`
- `aws.ssm.session.failed`

Latest Datadog Forwarder Documentation : https://docs.datadoghq.com/logs/guide/forwarder/?tab=cloudformation#overview

### 2.1 Deploy the Datadog Forwarder

```bash
aws cloudformation create-stack \
  --stack-name datadog-forwarder \
  --template-url https://datadog-cloudformation-template.s3.amazonaws.com/aws/forwarder/latest.yaml \
  --parameters \
    ParameterKey=DdApiKey,ParameterValue=YOUR_DATADOG_API_KEY \
    ParameterKey=DdSite,ParameterValue=datadoghq.com \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
```

Wait for the stack to complete before proceeding.

```bash
aws cloudformation wait stack-create-complete \
  --stack-name datadog-forwarder
```

Retrieve the Forwarder Lambda ARN.

```bash
aws cloudformation describe-stacks \
  --stack-name datadog-forwarder \
  --query "Stacks[0].Outputs[?OutputKey=='DatadogForwarderArn'].OutputValue" \
  --output text
```

### 2.2 Subscribe the CloudTrail Log Group

Replace `YOUR_LOG_GROUP` with your CloudTrail log group name and
`FORWARDER_ARN` with the ARN from the previous step.

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
> relies on CloudTrail events from the management account. Subscribe the
> management account CloudTrail log group to a Forwarder instance deployed
> in the management account.

### 2.3 Create Log-based Metrics in Datadog

Once logs are flowing, go to **Logs > Generate Metrics** in Datadog and select
**New Metric** for each entry below.

| Metric Name | Filter Query | Type | Recommended Tags |
|---|---|---|---|
| `aws.cloudtrail.unauthorized_api_calls` | `source:cloudtrail @errorCode:(UnauthorizedOperation OR AccessDenied*)` | Count | `@awsRegion`, `@errorCode`, `@userIdentity.arn` |
| `aws.cloudtrail.root_activity` | `source:cloudtrail @userIdentity.type:Root NOT @userIdentity.invokedBy:* @eventType:AwsApiCall` | Count | `@awsRegion`, `@eventName` |
| `aws.organizations.scp.denied_requests` | `source:cloudtrail @errorCode:AccessDenied @errorMessage:*service\ control\ policy*` | Count | `@awsRegion`, `@userIdentity.arn`, `@errorCode` |
| `aws.ssm.session.failed` | `source:cloudtrail @eventSource:ssm.amazonaws.com @eventName:StartSession @errorCode:*` | Count | `@awsRegion`, `@userIdentity.arn`, `@errorCode` |

### 2.4 Alternative: CloudWatch Logs Metric Filters

If you are not forwarding logs to Datadog and do not wish to deploy the
Forwarder, create CloudWatch metric filters directly on the CloudTrail log
group and then add `CloudTrailMetrics` as a custom namespace in the Datadog
AWS integration Metric Collection tab.

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

**SSM session failures:**

```bash
aws logs put-metric-filter \
  --log-group-name "YOUR_LOG_GROUP" \
  --filter-name "SSMSessionFailed" \
  --filter-pattern '{ $.eventSource = "ssm.amazonaws.com" && $.eventName = "StartSession" && $.errorCode EXISTS }' \
  --metric-transformations \
    metricName="SSMSessionFailed",metricNamespace="CloudTrailMetrics",metricValue=1,defaultValue=0
```

Use the **Metric Renaming** feature in the Datadog AWS integration to map
CloudWatch-generated names to your target metric names.

---

## Part 3: AWS Security Hub Integration

AWS Security Hub aggregates compliance findings from Config rules, Control
Tower guardrails, and other security services. The Datadog AWS integration
pulls these findings natively.

> **Important:** Security Hub provides **findings (logs)**, not timeseries
> metrics. This makes it well suited for compliance reporting and security
> investigation in Datadog. For metric-based alerting and dashboards that
> require numeric count or gauge values, use **Part 4 (Lambda)** instead,
> which submits direct timeseries metrics.

**Coverage:**
- `aws.config.rule.non_compliant` (compliance reporting path)
- `aws.config.public_resource_detected` (compliance reporting path)
- `aws.controltower.guardrail.failed` (compliance reporting path)
- `aws.controltower.logging.disabled` (compliance reporting path)

### 3.1 Enable AWS Security Hub

```bash
aws securityhub enable-security-hub \
  --enable-default-standards \
  --region YOUR_REGION
```

### 3.2 Enable Standards and the Config Integration

```bash
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {
      "StandardsArn": "arn:aws:securityhub:REGION::standards/aws-foundational-security-best-practices/v/1.0.0"
    },
    {
      "StandardsArn": "arn:aws:securityhub:REGION::standards/cis-aws-foundations-benchmark/v/1.2.0"
    }
  ]'

aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:REGION::product/aws/config
```

### 3.3 Configure the Datadog Integration

1. In Datadog go to **Integrations > Amazon Security Hub**
2. Select the AWS account and region
3. Enable the integration and save

Findings from Config rules and Control Tower guardrails will appear in Datadog
under **Security > Findings** and in the **Logs Explorer** with
`source:aws_securityhub`.

### 3.4 Create Log-based Metrics from Security Hub Findings

To produce numeric timeseries from Security Hub findings, go to
**Logs > Generate Metrics** in Datadog and create the following metrics.

| Metric Name | Filter Query | Type | Recommended Tags |
|---|---|---|---|
| `aws.config.rule.non_compliant` | `source:aws_securityhub @compliance.status:FAILED @product.name:"AWS Config"` | Count | `@aws.account.id`, `@aws.region`, `@compliance.rule_id` |
| `aws.config.public_resource_detected` | `source:aws_securityhub @compliance.status:FAILED @product.name:"AWS Config" (@compliance.rule_id:*public* OR @compliance.rule_id:*Public*)` | Count | `@aws.account.id`, `@aws.region`, `@compliance.rule_id`, `@resource.id` |
| `aws.controltower.guardrail.failed` | `source:aws_securityhub @compliance.status:FAILED @product.name:"AWS Control Tower"` | Count | `@aws.account.id`, `@aws.region`, `@compliance.rule_id` |
| `aws.controltower.logging.disabled` | `source:aws_securityhub @compliance.status:FAILED @product.name:"AWS Config" (@compliance.rule_id:*cloudtrail* OR @compliance.rule_id:*log*)` | Count | `@aws.account.id`, `@aws.region`, `@compliance.rule_id` |

> **Note:** Field names in Security Hub findings can vary. Use the Logs
> Explorer to inspect actual finding structure and adjust queries accordingly.
> Common fields include `@compliance.status`, `@product.name`,
> `@compliance.rule_id`, `@aws.account.id`, and `@aws.region`.

### 3.5 Recommended Path for Metric-Based Alerting

If you need low-latency numeric timeseries metrics for monitor-based alerting,
use the Lambda handlers in Part 4 rather than the log-based metric approach
above. The Lambda approach:

- Submits count metrics directly at the point of the event with no log
  ingestion delay
- Does not depend on Security Hub finding ingestion timing
- Is better suited to threshold-based monitors that need immediate notification

Enable the EventBridge rules for `aws.config` and `aws.controltower` from the
rule list in Part 4 to activate these handlers alongside the rest of the Lambda
integration.

---

## Part 4: EventBridge Lambda Integration

For services that emit events through EventBridge rather than CloudWatch, a
Lambda function parses each event and submits a metric to Datadog via the
metrics API. This part is also the recommended path for compliance metrics
that require reliable numeric timeseries for alerting.

### 4.1 Lambda Function

Create a file named `lambda_function.py` with the following code.

```python
import json
import os
import time
import boto3
import urllib.request
from datetime import datetime, timedelta, timezone


# ── Metric Submission ──────────────────────────────────────────────────────────

# Cache the API key within the Lambda execution context to reduce
# Secrets Manager API calls across multiple invocations of the same instance
_api_key_cache = None


def get_api_key():
    global _api_key_cache
    if _api_key_cache is None:
        secret_arn = os.environ["DD_API_KEY_SECRET_ARN"]
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=secret_arn)
        _api_key_cache = response["SecretString"]
    return _api_key_cache


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


# ── Pollers (Scheduled) ────────────────────────────────────────────────────────

def run_pollers():
    poll_drs_cloudwatch_metrics()
    report_managed_instance_status()
    report_patch_compliance()
    report_drs_test_failures()


def poll_drs_cloudwatch_metrics():
    """
    Used for Part 1 Option B (Lambda polling fallback) only.
    If you are using CloudWatch Metric Streams from Part 1 Option A,
    remove this call from run_pollers() to avoid duplicate submissions.
    """
    cw = boto3.client("cloudwatch")
    drs_client = boto3.client("drs")
    paginator = drs_client.get_paginator("describe_source_servers")

    for page in paginator.paginate():
        for server in page.get("items", []):
            server_id = server.get("sourceServerID", "unknown")

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=5)

            for cw_name, dd_name in [
                ("ReplicationLag", "aws.drs.replication_lag"),
                ("RecoveryPointAge", "aws.drs.recovery_point_age"),
            ]:
                response = cw.get_metric_statistics(
                    Namespace="AWS/DRS",
                    MetricName=cw_name,
                    Dimensions=[
                        {"Name": "SourceServerID", "Value": server_id}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=300,
                    Statistics=["Average"]
                )
                datapoints = response.get("Datapoints", [])
                if datapoints:
                    value = datapoints[-1]["Average"]
                    tags = [f"source_server_id:{server_id}"]
                    submit_metric(dd_name, value, tags, "gauge")


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

    # boto3 returns timezone-aware datetime objects from AWS APIs.
    # cutoff is also timezone-aware to ensure a valid comparison.
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    for page in paginator.paginate():
        for job in page.get("items", []):
            if job.get("initiatedBy", "") not in ("START_DRILL", "DRILL"):
                continue

            creation_time = job.get("creationDateTime")
            # Ensure creation_time is timezone-aware before comparing
            if creation_time:
                if creation_time.tzinfo is None:
                    creation_time = creation_time.replace(tzinfo=timezone.utc)
                if creation_time < cutoff:
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

> **Note for Control Tower:** Control Tower events originate in the management
> account. Deploy the Lambda and EventBridge rules there or configure
> cross-account EventBridge routing to forward events to the account where
> the Lambda runs.

---

## Part 5: Scheduled Lambda for Polling-Based Metrics

Three metrics require periodic API polling and have no simpler alternative.
These are handled by the `run_pollers()` function in the Lambda above.

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
          "drs:DescribeJobs",
          "drs:DescribeSourceServers",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
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

Navigate to **Metrics > Explorer** and search for the metric name.

| Collection Method | Expected Delay |
|---|---|
| Lambda and API | 2 to 3 minutes |
| Metric Streams | 2 to 5 minutes |
| Forwarder and log-based metrics | Available as soon as logs flow through the Forwarder |
| CloudWatch metric filters | Up to 15 minutes |

If a metric does not appear after the expected window, check:

- Lambda CloudWatch Logs for errors in the function output
- That the Datadog API key in Secrets Manager is stored as a plaintext string
  and has not expired
- That the EventBridge rule is in `ENABLED` state with the correct Lambda ARN
  as the target
- For Metric Streams, that the stream state is `RUNNING` and the Firehose
  delivery stream is active
- For the Forwarder, that the log group subscription filter is in place and
  the Forwarder Lambda is receiving invocations

---

## Part 8: Recommended Monitors

Once data is flowing, create monitors under **Monitors > New Monitor > Metric**
in Datadog or define them using the
[Datadog Terraform provider](https://registry.terraform.io/providers/DataDog/datadog/latest).

| Monitor | Metric | Recommended Condition |
|---|---|---|
| DRS replication lag | `aws.drs.replication_lag` | Alert when value exceeds 300 seconds for any source server |
| DRS recovery point age | `aws.drs.recovery_point_age` | Alert when value exceeds your RPO threshold |
| DRS instance not ready | `aws.drs.recovery_instance_ready` | Alert when gauge drops to 0 for any source server |
| Backup job failures | `aws.backup.backupjobfailed` | Alert when count is greater than zero in any 30-minute window |
| Config non-compliance | `aws.config.rule.non_compliant` | Alert on count increase above baseline over 15 minutes |
| Public resource detected | `aws.config.public_resource_detected` | Alert immediately on any non-zero count |
| Root account activity | `aws.cloudtrail.root_activity` | Alert immediately on any non-zero value |
| Unauthorized API calls | `aws.cloudtrail.unauthorized_api_calls` | Alert on count exceeding rolling baseline |
| Control Tower guardrail failures | `aws.controltower.guardrail.failed` | Alert on any non-zero count |
| Control Tower drift | `aws.controltower.account.drift` | Alert on any non-zero count |
| SCP denied requests | `aws.organizations.scp.denied_requests` | Alert on threshold breach |
| SSM patch compliance drop | `aws.ssm.patch.compliance` | Alert when average drops below your compliance target |
| SSM instance offline | `aws.ssm.managed_instance.online` | Alert when gauge drops to 0 for any instance |
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
  only the event types needed for the metrics in this guide

### AWS Kinesis Data Firehose (Part 1 Metric Streams path)
- Firehose charges per GB of data processed
- Streaming all CloudWatch namespaces rather than filtering to `AWS/DRS` only
  will increase data volume proportionally

### AWS Lambda
- Event-driven Lambdas are low cost at normal alert volumes
- A spike in Config non-compliance events, SSM command failures, or Control
  Tower guardrail violations triggers a proportional spike in Lambda invocations
- Scheduled Lambdas run continuously regardless of activity level

### AWS CloudWatch
- CloudWatch Logs metric filters are free to create but the custom metrics
  they publish are billed as CloudWatch custom metrics
- CloudTrail log storage costs apply if not already accounted for

### AWS Secrets Manager
- Each Lambda invocation calls Secrets Manager to retrieve the Datadog API key
- The API key is cached within the Lambda execution context in this guide to
  reduce Secrets Manager calls across warm invocations of the same instance

### AWS EventBridge
- Events on the default bus from AWS services are free
- Cross-account routing through a custom event bus incurs a per-event charge
  and should be reviewed if forwarding Control Tower events across many accountsAdd to Conversation
