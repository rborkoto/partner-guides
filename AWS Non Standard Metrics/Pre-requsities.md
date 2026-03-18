# Prerequisites Guide

This document covers everything that must be in place before following the metrics import guide. Work through each section in order before proceeding with any configuration steps.

---
Note : You can also use the CF template directly from Datadog UI instead of doing this via CLI

## 1. Datadog AWS Integration with IAM Cross-Account Role

Datadog accesses your AWS account using a cross-account IAM role. You create the role in your AWS account and provide the role ARN to Datadog.

### 1.1 Create the IAM Role

In your AWS account, create a new IAM role with the following trust policy. Replace `YOUR_DATADOG_EXTERNAL_ID` with the External ID shown in the Datadog AWS integration tile under **Integrations > Amazon Web Services > Add Account**.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::464622532012:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "YOUR_DATADOG_EXTERNAL_ID"
        }
      }
    }
  ]
}
```

### 1.2 Attach the Required Policy

Attach the AWS managed policy `SecurityAudit` and the following inline policy to allow Datadog to collect metrics and resource data.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricStatistics",
        "tag:GetResources",
        "tag:GetTagKeys",
        "tag:GetTagValues"
      ],
      "Resource": "*"
    }
  ]
}
```

For the full list of permissions required by the Datadog integration, refer to the [Datadog AWS Integration IAM documentation](https://docs.datadoghq.com/integrations/amazon_web_services/?tab=roledelegation#iam-role).

### 1.3 Register the Role in Datadog

1. In Datadog, go to **Integrations > Amazon Web Services**
2. Select **Add AWS Account**
3. Enter your AWS Account ID and the name of the IAM role you created
4. Save and verify the integration status shows as green

### 1.4 Verify

```bash
aws sts get-caller-identity
```

Confirm the integration is active in Datadog by checking that AWS host data begins appearing under **Infrastructure > Host Map** within 15 minutes.

---

## 2. AWS CloudTrail with CloudWatch Logs Delivery

CloudTrail must be configured to deliver log events to a CloudWatch Logs log group. This is required for the metric filter approach used by several metrics in this guide.

### 2.1 Confirm an Active Trail

```bash
aws cloudtrail describe-trails --include-shadow-trails false
```

If no trails are returned, create one:

```bash
aws cloudtrail create-trail \
  --name organisation-audit-trail \
  --s3-bucket-name YOUR_CLOUDTRAIL_S3_BUCKET \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging \
  --name organisation-audit-trail
```

### 2.2 Create a CloudWatch Logs Log Group

```bash
aws logs create-log-group --log-group-name /aws/cloudtrail/audit-logs
```

### 2.3 Create an IAM Role for CloudTrail to Write to CloudWatch Logs

CloudTrail requires its own IAM role to deliver events to CloudWatch Logs.

```bash
aws iam create-role \
  --role-name CloudTrailCloudWatchRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name CloudTrailCloudWatchRole \
  --policy-name CloudTrailCloudWatchPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/cloudtrail/audit-logs:*"
    }]
  }'
```

### 2.4 Associate the Log Group with the Trail

```bash
aws cloudtrail update-trail \
  --name organisation-audit-trail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/cloudtrail/audit-logs \
  --cloud-watch-logs-role-arn arn:aws:iam::ACCOUNT_ID:role/CloudTrailCloudWatchRole
```

### 2.5 Verify

```bash
aws cloudtrail get-trail-status --name organisation-audit-trail
```

Confirm `IsLogging` is `true` and `LatestCloudWatchLogsDeliveryTime` shows a recent timestamp.

> **Note for multi-account setups:** SCP-related CloudTrail events originate in the management account. The trail and log group for `aws.organizations.scp.denied_requests` must be configured in the management account, not a member account.

---

## 3. IAM Permissions for Resource Creation

The IAM principal (user or role) running the deployment steps in this guide requires permissions to create and manage the following resource types.

### 3.1 Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchMetricFilters",
      "Effect": "Allow",
      "Action": [
        "logs:PutMetricFilter",
        "logs:DeleteMetricFilter",
        "logs:DescribeMetricFilters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EventBridgeRules",
      "Effect": "Allow",
      "Action": [
        "events:PutRule",
        "events:PutTargets",
        "events:DescribeRule",
        "events:DeleteRule",
        "events:RemoveTargets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaManagement",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:AddPermission",
        "lambda:GetFunction",
        "lambda:InvokeFunction"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMRoleManagement",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "iam:GetRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:datadog/*"
    },
    {
      "Sid": "CloudFormationManagement",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
        "cloudformation:WaitStackCreateComplete",
        "cloudformation:DescribeStackEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KinesisFirehoseManagement",
      "Effect": "Allow",
      "Action": [
        "firehose:CreateDeliveryStream",
        "firehose:DescribeDeliveryStream",
        "firehose:ListDeliveryStreams",
        "firehose:TagDeliveryStream"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchMetricStreams",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricStream",
        "cloudwatch:GetMetricStream",
        "cloudwatch:ListMetricStreams",
        "cloudwatch:DeleteMetricStream"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Management",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:GetBucketLocation",
        "s3:PutBucketPolicy",
        "s3:GetBucketPolicy",
        "s3:PutBucketVersioning"
      ],
      "Resource": "arn:aws:s3:::YOUR_BACKUP_BUCKET"
    }
  ]
}
```

### 3.2 Verify Your Current Permissions

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT_ID:user/YOUR_USER \
  --action-names lambda:CreateFunction events:PutRule logs:PutMetricFilter cloudformation:CreateStack firehose:CreateDeliveryStream cloudwatch:PutMetricStream \
  --resource-arns "*"
```

> **Note:** Replace `YOUR_BACKUP_BUCKET` in the S3 permissions with your actual S3 bucket name. If you plan to use CloudWatch Metric Streams (Part 1, Option A), you'll need an S3 bucket for Firehose backup. See section 7 for S3 bucket setup.

---

## 4. Datadog API Key in AWS Secrets Manager

The Lambda functions in this guide retrieve the Datadog API key from Secrets Manager at runtime. The secret must be stored as a plaintext string, not as a JSON key-value pair.

### 4.1 Retrieve Your Datadog API Key

In Datadog, go to **Organization Settings > API Keys** and copy an existing key or create a new one scoped for this integration.

### 4.2 Store the Secret

```bash
aws secretsmanager create-secret \
  --name datadog/api-key \
  --description "Datadog API key for AWS metrics Lambda functions" \
  --secret-string "YOUR_DATADOG_API_KEY_VALUE"
```

> **Note:** Note the ARN returned by this command. You will need it when setting the `DD_API_KEY_SECRET_ARN` environment variable on each Lambda function.

### 4.3 Verify

```bash
aws secretsmanager get-secret-value \
  --secret-id datadog/api-key \
  --query SecretString \
  --output text
```

The raw API key value should be returned. If JSON is returned instead, the secret was stored incorrectly and the Lambda functions will fail to authenticate with Datadog.

---

## 5. Python 3.12 Runtime for Lambda

All Lambda functions in this guide target the Python 3.12 runtime. No additional libraries beyond the AWS SDK (boto3) and the Python standard library are required, as both are included in the Lambda execution environment by default.

### 5.1 Verify Python Version Availability in Your Region

```bash
aws lambda list-layers \
  --compatible-runtime python3.12 \
  --region YOUR_REGION
```

Python 3.12 is available in all commercial AWS regions. If your environment enforces a specific approved runtime list, confirm Python 3.12 is on it before proceeding.

---

## 6. AWS CLI Configuration

All deployment commands in this guide use the AWS CLI. Confirm it is installed and configured before proceeding.

### 6.1 Install the AWS CLI

Follow the [official installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) for your operating system, or verify an existing installation:

```bash
aws --version
```

The output should show version 2.x or higher.

### 6.2 Configure Credentials

```bash
aws configure
```

You will be prompted for:

| Field | Value |
|---|---|
| AWS Access Key ID | Your IAM user or assumed role access key |
| AWS Secret Access Key | Corresponding secret key |
| Default region name | The AWS region where resources will be deployed |
| Default output format | `json` |

### 6.3 Verify the Active Identity

```bash
aws sts get-caller-identity
```

Confirm the returned `Account`, `UserId`, and `Arn` match the account and principal you intend to use for this deployment.

### 6.4 Multi-Account Deployments

If you are deploying resources across multiple accounts (for example, placing the Control Tower event rules in the management account while the Lambda runs in a workload account), configure named profiles for each account:

```bash
aws configure --profile management-account
aws configure --profile workload-account
```

Pass `--profile PROFILE_NAME` to each CLI command where the target account differs from your default.

---

## 7. S3 Bucket for CloudWatch Metric Streams (Optional)

If you plan to use CloudWatch Metric Streams (Part 1, Option A) for DRS metrics, you need an S3 bucket for Firehose backup. This bucket stores failed delivery attempts.

### 7.1 Create S3 Bucket

```bash
aws s3 mb s3://YOUR_BACKUP_BUCKET --region YOUR_REGION
```

### 7.2 Enable Versioning (Recommended)

```bash
aws s3api put-bucket-versioning \
  --bucket YOUR_BACKUP_BUCKET \
  --versioning-configuration Status=Enabled
```

### 7.3 Apply Lifecycle Policy (Optional)

To manage costs, add a lifecycle policy to delete old backup files:

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket YOUR_BACKUP_BUCKET \
  --lifecycle-configuration '{
    "Rules": [{
      "Id": "DeleteOldBackups",
      "Status": "Enabled",
      "Expiration": {"Days": 30}
    }]
  }'
```

> **Note:** Replace `YOUR_BACKUP_BUCKET` with your chosen bucket name. The bucket name must be globally unique across all AWS accounts.

---

## 8. AWS Security Hub (Optional)

If you plan to use the Security Hub integration (Part 3) for Config and Control Tower compliance metrics, Security Hub must be enabled. However, note that Security Hub provides findings (logs), not direct metrics. For metric-based alerting, the Lambda approach in Part 4 is recommended.


---

## Prerequisites Checklist

Before moving to the main guide, confirm each item below is complete.

- [ ] Datadog AWS integration is active and showing green in the integration tile
- [ ] CloudTrail trail is enabled, logging, and delivering to a CloudWatch Logs log group
- [ ] Your deployment principal has the IAM permissions listed in Section 3 (including CloudFormation, Firehose, and Metric Streams permissions if using those features)
- [ ] Datadog API key is stored as a plaintext secret in Secrets Manager and the ARN is noted
- [ ] Python 3.12 runtime is available and approved in your environment
- [ ] AWS CLI is installed, configured, and `get-caller-identity` returns the expected account
- [ ] (Optional) S3 bucket created for CloudWatch Metric Streams backup if using Part 1, Option A
