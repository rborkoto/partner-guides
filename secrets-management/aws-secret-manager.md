# Datadog Secrets Management — AWS-Primary Multi-Cloud Implementation Guide

> **Scope:** Supplementary to the Datadog Secrets Management Strategy (v0.9). This guide is
> written for customers where **AWS is the primary cloud**, Azure and GCP are secondary workloads,
> and **physical/virtual network devices** (routers, switches, firewalls) are monitored via SNMP
> collectors running on **on-premises VMs**.
>
> IaC tooling patterns are written to be **tooling-agnostic** — configuration structures and
> commands are shown as first principles so they can be adapted to Terraform, Pulumi, CloudFormation,
> Ansible, or manual provisioning.
>
> **Note:** This is not official Datadog documentation. Always cross-reference with
> [docs.datadoghq.com](https://docs.datadoghq.com).

---

## Table of Contents

1. [Architecture Overview and Secret Store Strategy](#1-architecture-overview)
2. [Secret Taxonomy: What Credentials Exist and Where](#2-secret-taxonomy)
3. [AWS Secrets Manager: Structure, Naming, and IAM Design](#3-aws-secrets-manager-structure)
4. [AWS-Hosted Workloads: EC2 and EKS](#4-aws-hosted-workloads)
5. [On-Premises VMs: SNMP Collectors and VM-Based Agents](#5-on-premises-vms)
6. [Network Device Monitoring: SNMP Collector Architecture](#6-network-device-monitoring)
7. [Azure and GCP Extension Scenarios](#7-azure-and-gcp-extension)
8. [Collector-Specific Configuration Reference](#8-collector-specific-configuration)
9. [Custom Integration and DogStatsD Patterns](#9-custom-integrations)
10. [Service-by-Service Secret Mapping Reference](#10-service-by-service-mapping)
11. [IaC Provisioning Patterns (Tooling-Agnostic)](#11-iac-provisioning-patterns)
12. [Secret Rotation Runbook](#12-rotation-runbook)
13. [Validation and Smoke Testing](#13-validation-and-smoke-testing)

---

## 1. Architecture Overview

### 1.1 Recommended Secret Store Strategy

For an AWS-primary environment with on-premises network device collectors, the recommended
approach is **AWS Secrets Manager as the single secret store for all platforms**, including
on-prem SNMP collector hosts.

This is preferable to a per-cloud store strategy here because:

- AWS is where the majority of workloads and credentials already live.
- On-prem SNMP collectors have no cloud-native identity — they need an explicit auth mechanism
  regardless of which store is used. AWS STS AssumeRole (from a low-privilege bootstrap key) is
  well-documented and auditable via CloudTrail.
- Azure and GCP workloads are secondary and can authenticate to AWS Secrets Manager using IAM
  Roles Anywhere, avoiding the operational overhead of managing two additional secret stores today.
  If Azure or GCP workloads grow significantly, migrating to per-cloud stores is straightforward
  since ENC[] handle paths can be kept identical across stores.

> **When to reconsider:** If Azure or GCP workloads reach parity with AWS in scale or if
> compliance requirements mandate data residency within each cloud, switch to Option B
> (per-cloud native stores) as documented in the Multi-Cloud Implementation Guide.

### 1.2 Platform-to-Authentication Map

| Platform | Auth Method | Notes |
|---|---|---|
| EC2 (AWS) | IAM instance profile | Automatic — no credentials in config |
| EKS (AWS) | IAM Roles for Service Accounts (IRSA) | Annotate Datadog ServiceAccount |
| On-prem VMs (SNMP collectors) | STS AssumeRole via bootstrap IAM key | One IAM user per datacenter |
| On-prem VMs (general Agent) | STS AssumeRole via bootstrap IAM key | Same pattern as collectors |
| Azure VMs | IAM Roles Anywhere (X.509) or static credentials | Roles Anywhere for prod; static for dev |
| AKS | IAM Roles Anywhere via `credential_process` | More complex — evaluate per-cloud store if AKS grows |
| GCE/GKE | IAM Roles Anywhere or static credentials | Same trade-off as Azure |

### 1.3 What the Datadog Agent Resolves vs. What It Inherits

A common implementation mistake is routing credentials through `secret_backend_command` that
the Agent does not actually need. Clarifying this upfront prevents over-engineering.

| Component | Needs ENC[] secrets? | What it uses |
|---|---|---|
| Infrastructure checks (MySQL, PostgreSQL, Redis, etc.) | **Yes** | Per-integration credentials in `conf.yaml` |
| SNMP / NDM collector | **Yes** | `community_string`, `authKey`, `privKey` |
| Custom checks | **Yes** | Application-specific tokens or passwords |
| APM / Trace Agent | No | Inherits `api_key` from `datadog.yaml` |
| Log Agent | No | Inherits `api_key` from `datadog.yaml` |
| Process Agent | No | Runs as Agent sub-process, inherits auth |
| NPM / System Probe | No | Uses kernel eBPF calls — no external credentials |
| Cluster Agent (Kubernetes) | Auth token only | Internal K8s Secret — not ENC[] |

---

## 2. Secret Taxonomy

Map every secret before provisioning anything. This table is the single reference for what
credentials exist, which Agent component consumes them, and how they rotate.

### 2.1 Agent-Level Secrets

| Handle | Content Type | Rotation Path |
|---|---|---|
| `dd/<env>/agent/api_key` | Plain string | Hot-reload via `secret_refresh_interval` — **no restart** |
| `dd/<env>/agent/app_key` | Plain string | Hot-reload via `secret_refresh_interval` — **no restart** |

### 2.2 Integration Secrets

| Handle | Content | Integration | Rotation |
|---|---|---|---|
| `dd/<env>/mysql/creds` | `{"username":"...","password":"..."}` | MySQL, RDS MySQL | Agent restart required |
| `dd/<env>/postgres/creds` | `{"username":"...","password":"..."}` | PostgreSQL, RDS PostgreSQL | Agent restart required |
| `dd/<env>/redis/password` | Plain string | Redis, ElastiCache | Agent restart required |
| `dd/<env>/mongodb/creds` | `{"username":"...","password":"..."}` | MongoDB, DocumentDB | Agent restart required |
| `dd/<env>/snmp/<device-group>` | `{"auth_key":"...","priv_key":"..."}` | SNMPv3 NDM | Agent restart required |
| `dd/<env>/snmp/<device-group>-community` | Plain string | SNMPv2c NDM | Agent restart required |
| `dd/<env>/custom/<check>/token` | Plain string or JSON | Custom checks | Agent restart required |

### 2.3 Credentials That Must NOT Route Through the Agent

| Credential | Where It Belongs |
|---|---|
| CI/CD pipeline API keys (GitHub Actions, GitLab, etc.) | CI/CD platform native secret store |
| Terraform Datadog provider key | CI runner environment variable or OIDC short-lived token |
| Argo CD / Flux repo credentials | GitOps tool's native secret management |
| Application DogStatsD keys | Application's own IAM role via SDK — not Agent secrets management |
| Observability Pipelines Worker credentials | OPW's own configuration — separate from the Agent |

---

## 3. AWS Secrets Manager: Structure, Naming, and IAM Design

### 3.1 Naming Convention

Use a hierarchical path that reflects environment, service, and credential purpose. The
`dd/<env>/` prefix enables environment-scoped IAM resource wildcards — a prod Agent role can
be restricted to `dd/prod/*` without managing individual ARNs.

```
dd/<env>/<service>/<credential>

Examples:
  dd/prod/agent/api_key
  dd/prod/agent/app_key
  dd/prod/mysql/creds
  dd/prod/postgres/creds
  dd/prod/redis/password
  dd/prod/mongodb/creds
  dd/prod/snmp/dc1_core_routers
  dd/prod/snmp/dc1_access_switches
  dd/prod/snmp/firewalls
  dd/staging/agent/api_key
  dd/staging/mysql/creds
```

### 3.2 Secret Content: Single-Value vs. JSON

**Single-value secrets** — use when the integration needs one credential:

```bash
aws secretsmanager create-secret \
  --name "dd/prod/agent/api_key" \
  --secret-string "your-datadog-api-key" \
  --kms-key-id "alias/datadog-prod"
```

```yaml
# datadog.yaml
api_key: ENC[dd/prod/agent/api_key]
```

**JSON secrets** — use when an integration needs username and password together. Packing them
into one secret halves the `GetSecretValue` call rate at Agent startup, which matters for
large fleets against the 5,000 req/sec/account quota:

```bash
aws secretsmanager create-secret \
  --name "dd/prod/mysql/creds" \
  --secret-string '{"username":"datadog","password":"db-password-here"}' \
  --kms-key-id "alias/datadog-prod"
```

```yaml
# conf.d/mysql.d/conf.yaml
instances:
  - host: prod-mysql.cluster.rds.amazonaws.com
    username: ENC[dd/prod/mysql/creds;username]
    password: ENC[dd/prod/mysql/creds;password]
```

The `;key` syntax extracts a single key from the JSON value. The Agent resolves
`ENC[dd/prod/mysql/creds;username]` by calling `GetSecretValue` for `dd/prod/mysql/creds`
once and extracting the `username` key from the returned JSON.

### 3.3 KMS Key Design

Use one customer-managed KMS key per environment. Do not share keys across prod and staging —
this prevents a staging credential misconfiguration from triggering prod key usage.

```bash
# Create prod KMS key
aws kms create-key \
  --description "Datadog Agent secrets — prod" \
  --key-usage ENCRYPT_DECRYPT \
  --tags TagKey=Environment,TagValue=prod \
         TagKey=ManagedBy,TagValue=terraform

aws kms create-alias \
  --alias-name "alias/datadog-prod" \
  --target-key-id <key-id>

# Enable automatic annual key rotation
aws kms enable-key-rotation --key-id <key-id>
```

### 3.4 IAM Role Design

Create separate IAM roles per environment and per deployment tier. A compromised EC2 instance
should not be able to read EKS secrets, and staging Agents must not be able to read prod
credentials.

| Role Name | Assigned To | Secret Scope |
|---|---|---|
| `dd-agent-ec2-prod` | EC2 prod instance profile | `dd/prod/*` |
| `dd-agent-ec2-staging` | EC2 staging instance profile | `dd/staging/*` |
| `dd-agent-irsa-prod` | EKS prod ServiceAccount (IRSA) | `dd/prod/*` |
| `dd-agent-irsa-staging` | EKS staging ServiceAccount (IRSA) | `dd/staging/*` |
| `dd-agent-onprem-prod` | On-prem VMs (AssumeRole target) | `dd/prod/*` |
| `dd-cluster-agent-irsa-prod` | Cluster Agent ServiceAccount | `dd/prod/agent/*` only |

**IAM policy template (scope per role by replacing `<env>`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsRead",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:dd/<env>/*"
    },
    {
      "Sid": "KMSDecrypt",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:<region>:<account-id>:key/<kms-key-id>"
    }
  ]
}
```

### 3.5 Secret Tagging

Tag every secret for cost attribution, access auditing, and rotation automation:

```bash
aws secretsmanager tag-resource \
  --secret-id "dd/prod/mysql/creds" \
  --tags Key=Environment,Value=prod \
         Key=ManagedBy,Value=datadog-agent \
         Key=Service,Value=mysql \
         Key=RotationRequired,Value=true
```

---

## 4. AWS-Hosted Workloads: EC2 and EKS

### 4.1 EC2 Configuration

Attach the `dd-agent-ec2-<env>` IAM instance profile to all EC2 instances running the Datadog
Agent. No credentials need to appear in `datadog.yaml` — the Agent uses the instance profile
automatically via the AWS SDK credential chain.

**`/etc/datadog-agent/datadog.yaml`:**

```yaml
# Agent-level secrets — resolved at startup
api_key: ENC[dd/prod/agent/api_key]
app_key: ENC[dd/prod/agent/app_key]
site: datadoghq.com

# Native AWS Secrets Manager backend (Agent 7.70+)
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    # No credentials — instance profile handles auth automatically

# Hot-reload API/APP keys without Agent restart
secret_refresh_interval: 3600

# Feature enablement
apm_config:
  enabled: true

logs_enabled: true

process_config:
  enabled: true
  process_collection: true
  scrub_args: true
  custom_sensitive_words:
    - "password"
    - "token"
    - "api_key"
    - "secret"

system_probe_config:
  enabled: true

network_config:
  enabled: true

# Fleet tags
tags:
  - env:prod
  - cloud:aws
  - managed_by:your-iac-tool
```

**Verify on any EC2 host after deployment:**

```bash
sudo datadog-agent secret
sudo datadog-agent status
```

### 4.2 EKS Configuration

**Step 1 — Create the IRSA role.** The trust policy must reference the cluster's OIDC provider.

```bash
# Get OIDC provider URL for the cluster
OIDC_URL=$(aws eks describe-cluster \
  --name prod-cluster \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed 's|https://||')

OIDC_ARN="arn:aws:iam::<account-id>:oidc-provider/${OIDC_URL}"
```

Trust policy (save as `irsa-trust-policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "<OIDC_ARN>" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "<OIDC_URL>:sub": "system:serviceaccount:datadog:datadog-agent"
      }
    }
  }]
}
```

```bash
aws iam create-role \
  --role-name dd-agent-irsa-prod \
  --assume-role-policy-document file://irsa-trust-policy.json

aws iam attach-role-policy \
  --role-name dd-agent-irsa-prod \
  --policy-arn arn:aws:iam::<account-id>:policy/DatadogSecretsRead-prod
```

**Step 2 — Helm values.** Annotate the ServiceAccount with the IRSA role ARN and configure
the native backend:

```yaml
# values-prod-eks.yaml
datadog:
  apiKey: ENC[dd/prod/agent/api_key]
  appKey: ENC[dd/prod/agent/app_key]
  site: datadoghq.com
  clusterName: prod-eks-us-east-1

  secretBackend:
    type: aws.secrets
    config:
      awsSession:
        awsRegion: us-east-1
        # No credentials — IRSA handles auth

  secretRefreshInterval: 3600

  apm:
    portEnabled: true
  logs:
    enabled: true
    containerCollectAll: true
  processAgent:
    enabled: true
    processCollection: true
  networkMonitoring:
    enabled: true

  tags:
    - env:prod
    - cloud:aws
    - cluster:prod-eks-us-east-1

  # Integration configs inline
  confd:
    mysql.yaml: |-
      instances:
        - host: prod-mysql.cluster.us-east-1.rds.amazonaws.com
          port: 3306
          username: ENC[dd/prod/mysql/creds;username]
          password: ENC[dd/prod/mysql/creds;password]
          tags:
            - service:mysql
            - env:prod

    postgres.yaml: |-
      instances:
        - host: prod-pg.cluster.us-east-1.rds.amazonaws.com
          port: 5432
          username: ENC[dd/prod/postgres/creds;username]
          password: ENC[dd/prod/postgres/creds;password]
          dbname: prod_db
          ssl: require
          tags:
            - service:postgres
            - env:prod

    redis.yaml: |-
      instances:
        - host: prod-redis.cache.amazonaws.com
          port: 6379
          password: ENC[dd/prod/redis/password]
          tags:
            - service:redis
            - env:prod

agents:
  image:
    tag: "7.77.0"
  rbac:
    serviceAccountAnnotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/dd-agent-irsa-prod

clusterAgent:
  enabled: true
  image:
    tag: "7.77.0"   # minimum for Cluster Agent native secrets support
  rbac:
    serviceAccountAnnotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/dd-cluster-agent-irsa-prod
```

> **Cluster Agent version note:** Native `secret_backend_type` for the Cluster Agent requires
> Agent 7.77+. If using an older Cluster Agent, fall back to `secret_backend_command` with a
> custom Python script. The node Agent IRSA role still handles auth in that case.

**Step 3 — Argo CD Application manifest:**

```yaml
# argocd/datadog-prod-eks.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: datadog-prod-eks
  namespace: argocd
spec:
  project: infrastructure
  source:
    repoURL: https://github.com/your-org/platform-configs
    targetRevision: main
    path: helm/datadog
    helm:
      valueFiles:
        - values-prod-eks.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: datadog
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

> **Important for Argo CD:** ENC[] handles are stored as literal strings in Git and synced
> as-is. The Agent resolves them at runtime. Do not use Argo CD's Vault plugin or Sealed Secrets
> for Agent integration secrets — it creates a double-decryption path that is harder to audit.

---

## 5. On-Premises VMs: SNMP Collectors and VM-Based Agents

On-prem hosts have no cloud-native identity. They must authenticate to AWS Secrets Manager
via explicit credentials. The recommended pattern is **STS AssumeRole from a low-privilege
bootstrap IAM key**, which limits blast radius and enables session-level CloudTrail logging.

### 5.1 Bootstrap IAM User Design

Create one IAM user per datacenter (not per host). The user has only one permission: to assume
the `dd-agent-onprem-prod` role. The role itself holds the Secrets Manager and KMS permissions.

```bash
# Create bootstrap IAM user
aws iam create-user --user-name dd-agent-bootstrap-dc1

# Policy: only allowed to assume the onprem Agent role
aws iam put-user-policy \
  --user-name dd-agent-bootstrap-dc1 \
  --policy-name AssumeDatadogRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<account-id>:role/dd-agent-onprem-prod"
    }]
  }'

# Create access key — store this in your secrets vault, not in the Agent config directly
aws iam create-access-key --user-name dd-agent-bootstrap-dc1
```

Trust policy for `dd-agent-onprem-prod` role (add to existing role):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<account-id>:user/dd-agent-bootstrap-dc1"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "dc1-datadog-prod"
      }
    }
  }]
}
```

The `ExternalId` condition prevents confused deputy attacks — any caller must know both the
role ARN and the external ID to assume it.

### 5.2 Credential Injection: systemd Drop-In (Linux)

Store the bootstrap key in your on-prem secrets vault or configuration management tool. Inject
it into the Agent process via a systemd drop-in rather than writing it to `datadog.yaml` — this
keeps credentials out of version control and out of Agent config dumps:

```bash
sudo mkdir -p /etc/systemd/system/datadog-agent.service.d
```

```ini
# /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
[Service]
Environment="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
Environment="AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/..."
Environment="AWS_DEFAULT_REGION=us-east-1"
```

```bash
sudo chmod 600 /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
sudo chown root:root /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
sudo systemctl daemon-reload
sudo systemctl restart datadog-agent
```

### 5.3 `datadog.yaml` for On-Prem Hosts

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[dd/prod/agent/api_key]
app_key: ENC[dd/prod/agent/app_key]
site: datadoghq.com

# Native AWS backend — AssumeRole via bootstrap key injected via systemd
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_role_arn: "arn:aws:iam::<account-id>:role/dd-agent-onprem-prod"
    aws_external_id: "dc1-datadog-prod"
    # No aws_access_key_id here — comes from systemd environment

secret_refresh_interval: 3600

# NPM requires system probe but is still relevant on-prem if traffic monitoring is needed
system_probe_config:
  enabled: false   # enable only if kernel 4.4.0+ and CAP_SYS_ADMIN available on-prem

logs_enabled: true
process_config:
  enabled: true

tags:
  - env:prod
  - cloud:onprem
  - datacenter:dc1
```

### 5.4 Backend Script Alternative (if Agent < 7.70)

If the on-prem Agent cannot be upgraded to 7.70+, use a custom Python script as
`secret_backend_command`. This also serves as the fallback when `secret_backend_type` is
unavailable for any reason.

```bash
sudo mkdir -p /etc/datadog-agent/secrets
```

```python
#!/usr/bin/env python3
# /etc/datadog-agent/secrets/fetch_secrets.py
# Use when secret_backend_type is unavailable (Agent < 7.70)
import json, sys, time, boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::<account-id>:role/dd-agent-onprem-prod"
EXTERNAL_ID = "dc1-datadog-prod"
MAX_RETRIES = 3
RETRY_DELAY = 2

def get_assumed_client():
    sts = boto3.client("sts", region_name=REGION)
    creds = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="datadog-agent-onprem",
        ExternalId=EXTERNAL_ID
    )["Credentials"]
    return boto3.client(
        "secretsmanager",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def get_secret(client, handle):
    parts = handle.split(";", 1)
    secret_id, json_key = parts[0], parts[1] if len(parts) == 2 else None

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.get_secret_value(SecretId=secret_id)
            raw = resp["SecretString"]
            if json_key:
                return json.loads(raw)[json_key], None
            return raw, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "AccessDeniedException"):
                return None, f"{code}: {secret_id}"
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                return None, str(e)
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                return None, str(e)

def main():
    payload = json.load(sys.stdin)
    try:
        client = get_assumed_client()
    except Exception as e:
        # If AssumeRole fails, return errors for all handles — do not exit(1)
        result = {h: {"value": None, "error": f"AssumeRole failed: {e}"}
                  for h in payload.get("secrets", [])}
        print(json.dumps(result))
        return

    result = {}
    for handle in payload.get("secrets", []):
        value, error = get_secret(client, handle)
        result[handle] = {"value": value, "error": error}
        if error:
            print(f"ERROR [{handle}]: {error}", file=sys.stderr)

    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

**`datadog.yaml` for script-based fallback:**

```yaml
api_key: ENC[dd/prod/agent/api_key]
site: datadoghq.com

secret_backend_command: /etc/datadog-agent/secrets/fetch_secrets.py
secret_backend_timeout: 30
secret_backend_output_max_size: 4194304
```

---

## 6. Network Device Monitoring: SNMP Collector Architecture

### 6.1 Collector Placement

Physical devices cannot be polled from EKS or arbitrary EC2 instances without network
reachability. For on-prem devices, the SNMP collector must run on a host that can reach the
device management plane (typically VLAN reachability to port 161 UDP).

**Recommended pattern: dedicated on-prem VM per datacenter**, running only the Datadog Agent
with SNMP and NDM enabled. This host uses the same STS AssumeRole pattern from Section 5.

Do not run SNMP collectors on the same hosts as application workloads. SNMP polling generates
significant socket activity and should be isolated to a dedicated collector host.

### 6.2 Device Group Secret Strategy

Create one secret per group of devices that shares the same credentials. Do not create one
secret per device — this generates excessive `GetSecretValue` calls and makes rotation
operationally expensive.

```
Typical groupings:

dd/prod/snmp/core_routers         Core router infrastructure (v3)
dd/prod/snmp/access_switches      Access layer switches (v2c or v3)
dd/prod/snmp/firewalls            Perimeter firewalls (v3)
dd/prod/snmp/dc_infrastructure    Out-of-band management devices (v2c)
```

```bash
# SNMPv2c community string
aws secretsmanager create-secret \
  --name "dd/prod/snmp/access_switches" \
  --secret-string "your-community-string" \
  --kms-key-id "alias/datadog-prod"

# SNMPv3 auth and privacy keys
aws secretsmanager create-secret \
  --name "dd/prod/snmp/core_routers" \
  --secret-string '{"auth_key":"your-auth-passphrase","priv_key":"your-priv-passphrase"}' \
  --kms-key-id "alias/datadog-prod"
```

### 6.3 SNMP Collector `conf.yaml`

```yaml
# /etc/datadog-agent/conf.d/snmp.d/conf.yaml
init_config:
  loader: core
  use_device_id_as_hostname: true
  oid_batch_size: 60

instances:

  # --- SNMPv2c: Access switches (subnet autodiscovery) ---
  - network_address: 10.0.10.0/24
    port: 161
    snmp_version: 2
    community_string: ENC[dd/prod/snmp/access_switches]
    collect_device_metadata: true
    tags:
      - device_group:access_switches
      - datacenter:dc1
      - env:prod

  # --- SNMPv3: Core routers (explicit IPs) ---
  - ip_address: 10.0.0.1
    port: 161
    snmp_version: 3
    user: dd_monitor
    authProtocol: SHA256
    authKey: ENC[dd/prod/snmp/core_routers;auth_key]
    privProtocol: AES256
    privKey: ENC[dd/prod/snmp/core_routers;priv_key]
    collect_device_metadata: true
    tags:
      - device_type:router
      - device_group:core_routers
      - datacenter:dc1
      - env:prod

  - ip_address: 10.0.0.2
    port: 161
    snmp_version: 3
    user: dd_monitor
    authProtocol: SHA256
    authKey: ENC[dd/prod/snmp/core_routers;auth_key]
    privProtocol: AES256
    privKey: ENC[dd/prod/snmp/core_routers;priv_key]
    collect_device_metadata: true
    tags:
      - device_type:router
      - device_group:core_routers
      - datacenter:dc1
      - env:prod

  # --- SNMPv3: Firewalls ---
  - ip_address: 10.0.0.254
    port: 161
    snmp_version: 3
    user: dd_monitor
    authProtocol: SHA256
    authKey: ENC[dd/prod/snmp/firewalls;auth_key]
    privProtocol: AES256
    privKey: ENC[dd/prod/snmp/firewalls;priv_key]
    collect_device_metadata: true
    tags:
      - device_type:firewall
      - device_group:firewalls
      - datacenter:dc1
      - env:prod
```

### 6.4 NDM Trap Receiver

If collecting SNMP traps, the receiver does not require device-side credentials for receiving
but uses community strings for trap authentication validation:

```yaml
# datadog.yaml — trap receiver section
network_devices:
  snmp_traps:
    enabled: true
    port: 9162
    bind_host: 0.0.0.0
    community_strings:
      - ENC[dd/prod/snmp/access_switches]
    stop_timeout: 5
```

### 6.5 `datadog.yaml` for the Dedicated SNMP Collector Host

```yaml
# /etc/datadog-agent/datadog.yaml — SNMP collector host
api_key: ENC[dd/prod/agent/api_key]
site: datadoghq.com

secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_role_arn: "arn:aws:iam::<account-id>:role/dd-agent-onprem-prod"
    aws_external_id: "dc1-datadog-prod"

secret_refresh_interval: 3600

# NDM-specific settings
network_devices:
  snmp_traps:
    enabled: true
    port: 9162

# Disable features not needed on the collector host
apm_config:
  enabled: false

process_config:
  enabled: false

system_probe_config:
  enabled: false

tags:
  - env:prod
  - role:snmp-collector
  - datacenter:dc1
```

### 6.6 SNMP Rotation Operational Note

SNMP credential rotation requires coordination with the network team and an Agent restart.
There is no hot-reload path for SNMP keys. Plan a brief maintenance window or rotate
sequentially per device group to minimize monitoring gaps:

```
1. Update device credentials on routers/switches (network team action).
2. Update secret in AWS Secrets Manager:
   aws secretsmanager put-secret-value \
     --secret-id dd/prod/snmp/core_routers \
     --secret-string '{"auth_key":"new-auth","priv_key":"new-priv"}'
3. Restart Agent on the SNMP collector host:
   sudo systemctl restart datadog-agent
4. Verify:
   sudo datadog-agent check snmp
   sudo datadog-agent secret
5. Confirm devices appear in Datadog Network Devices UI.
```

---

## 7. Azure and GCP Extension Scenarios

These sections apply when Azure or GCP workloads need to run the Datadog Agent against the
same AWS Secrets Manager store. If the Azure/GCP footprint grows significantly, evaluate
migrating to per-cloud native stores (AKV and GCP Secret Manager) using the same ENC[] handle
paths.

### 7.1 Azure VMs — IAM Roles Anywhere (Production)

IAM Roles Anywhere lets Azure VMs authenticate to AWS using X.509 certificates issued by a
CA you register with AWS. This eliminates long-lived static keys from Azure hosts.

**Prerequisites:** An internal PKI or AWS Private CA. Each Azure VM needs a unique certificate
signed by the registered CA.

```bash
# Register your CA with AWS
aws rolesanywhere create-trust-anchor \
  --name "DatadogAzureCA" \
  --source "sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData=$(base64 -w0 ca.pem)}" \
  --enabled

# Create a profile linking the anchor to the Agent IAM role
aws rolesanywhere create-profile \
  --name "DatadogAzureAgentProfile" \
  --role-arns "arn:aws:iam::<account-id>:role/dd-agent-azure-prod" \
  --enabled
```

On each Azure VM, install `aws_signing_helper` and configure an AWS profile:

```ini
# /home/dd-agent/.aws/config
[profile datadog-agent]
credential_process = aws_signing_helper credential-process \
  --certificate /etc/datadog-agent/secrets/agent.crt \
  --private-key /etc/datadog-agent/secrets/agent.key \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:<account-id>:trust-anchor/<anchor-id> \
  --profile-arn arn:aws:rolesanywhere:us-east-1:<account-id>:profile/<profile-id> \
  --role-arn arn:aws:iam::<account-id>:role/dd-agent-azure-prod
```

```yaml
# /etc/datadog-agent/datadog.yaml — Azure VM
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_profile: datadog-agent
```

### 7.2 Azure VMs — Static Credentials (Development / Staging)

For non-production Azure workloads where IAM Roles Anywhere is not yet set up, use static
credentials injected via systemd (same pattern as on-prem VMs in Section 5.2):

```ini
# /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
[Service]
Environment="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
Environment="AWS_SECRET_ACCESS_KEY=..."
Environment="AWS_DEFAULT_REGION=us-east-1"
```

```yaml
# /etc/datadog-agent/datadog.yaml — Azure VM (staging)
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_role_arn: "arn:aws:iam::<account-id>:role/dd-agent-azure-staging"
    aws_external_id: "azure-datadog-staging"
```

### 7.3 AKS / GKE — Evaluation Guidance

For Kubernetes workloads on AKS or GKE, the choice between AWS Secrets Manager (via IAM Roles
Anywhere / credential_process) and per-cloud native stores (AKV or GCP Secret Manager) depends
on cluster count and workload criticality:

| Scenario | Recommended Store |
|---|---|
| 1–2 AKS/GKE clusters, low criticality | AWS Secrets Manager via IAM Roles Anywhere + credential_process |
| 3+ AKS/GKE clusters or regulated workloads | Per-cloud native stores — AKV for AKS, GCP SM for GKE |
| Existing Azure Managed Identity or GCP Workload Identity already in use | Per-cloud native stores |

If per-cloud stores are chosen for AKS or GKE, refer to the Azure Key Vault and GCP Secret
Manager sections in the Datadog Secrets Management Strategy (v0.9) for Agent configuration.
The ENC[] handle naming convention should match `dd/<env>/<service>/<credential>` regardless
of store to keep integration `conf.yaml` files portable.

---

## 8. Collector-Specific Configuration Reference

### 8.1 Process Agent

The Process Agent runs as a sub-process of the main Agent and inherits API key authentication.
No ENC[] secrets needed. Configure scrubbing to prevent accidental credential exposure in
process argument collection:

```yaml
# datadog.yaml
process_config:
  enabled: true
  process_collection: true
  scrub_args: true
  custom_sensitive_words:
    - "password"
    - "passwd"
    - "secret"
    - "token"
    - "api_key"
    - "apikey"
    - "auth"
    - "credential"
```

### 8.2 APM / Trace Agent

Inherits `api_key` from `datadog.yaml`. No ENC[] needed. For APM in Kubernetes, the
application container uses `DD_AGENT_HOST` to locate the Agent — no API key in the application
container:

```yaml
# Application pod env vars — no Datadog secrets needed here
env:
  - name: DD_AGENT_HOST
    valueFrom:
      fieldRef:
        fieldPath: status.hostIP
  - name: DD_TRACE_AGENT_PORT
    value: "8126"
  - name: DD_ENV
    value: "prod"
  - name: DD_SERVICE
    value: "your-service-name"
  - name: DD_VERSION
    value: "1.0.0"
```

### 8.3 Log Agent

Inherits `api_key`. For container log collection in Kubernetes, no additional secrets are
needed. For log forwarding to an authenticated HTTP endpoint (non-Datadog), that credential
should go through the Agent secrets mechanism:

```yaml
# conf.d/http_log.d/conf.yaml — authenticated log endpoint example
logs:
  - type: http
    url: https://log-aggregator.internal/ingest
    headers:
      Authorization: ENC[dd/prod/custom/log-aggregator/token]
    source: app
    service: my-service
```

### 8.4 NPM / System Probe

No external credentials needed. Kernel and capability requirements:

```yaml
# datadog.yaml
system_probe_config:
  enabled: true

network_config:
  enabled: true
  enable_http_monitoring: true
```

For Kubernetes, NPM requires the Agent DaemonSet to run with `hostNetwork: true` and the
`SYS_ADMIN` capability. These are set in the Datadog Helm chart via:

```yaml
# values.yaml
datadog:
  networkMonitoring:
    enabled: true
agents:
  podSecurity:
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW"]
```

### 8.5 Cluster Agent

The Cluster Agent uses an internal auth token shared with node Agents. This is a Kubernetes
Secret — do not route it through ENC[]:

```bash
kubectl create secret generic datadog-cluster-agent-token \
  --from-literal=token=$(openssl rand -hex 32) \
  -n datadog
```

```yaml
# Helm values
clusterAgent:
  tokenExistingSecret: datadog-cluster-agent-token
```

---

## 9. Custom Integrations and DogStatsD Patterns

### 9.1 Python Custom Check

ENC[] handles in `conf.yaml` are resolved by the Agent before your `check()` method is called.
The token arrives as a plain string in the `instance` dict — no boto3 or secrets API calls
inside the check.

```yaml
# conf.d/my_internal_api.d/conf.yaml
instances:
  - endpoint: https://internal-api.prod.internal/metrics
    api_token: ENC[dd/prod/custom/internal-api/token]
    timeout: 15
    tags:
      - service:internal-api
      - env:prod
```

```python
# checks.d/my_internal_api.py
from datadog_checks.base import AgentCheck
import requests

class MyInternalApiCheck(AgentCheck):
    def check(self, instance):
        endpoint = instance["endpoint"]
        api_token = instance["api_token"]   # already plaintext — Agent resolved ENC[]
        timeout = instance.get("timeout", 15)

        try:
            resp = requests.get(
                endpoint,
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=timeout
            )
            resp.raise_for_status()
            data = resp.json()

            self.gauge(
                "my_internal_api.response_time_ms",
                resp.elapsed.total_seconds() * 1000,
                tags=instance.get("tags", [])
            )
            self.service_check(
                "my_internal_api.can_connect",
                AgentCheck.OK,
                tags=instance.get("tags", [])
            )
        except Exception as e:
            self.service_check(
                "my_internal_api.can_connect",
                AgentCheck.CRITICAL,
                message=str(e),
                tags=instance.get("tags", [])
            )
```

### 9.2 Autodiscovery Custom Check (Kubernetes Pod Annotations)

```yaml
# Pod annotation — ENC[] in annotation value is resolved by the Agent
metadata:
  annotations:
    ad.datadoghq.com/mycontainer.check_names: '["my_internal_api"]'
    ad.datadoghq.com/mycontainer.init_configs: '[{}]'
    ad.datadoghq.com/mycontainer.instances: |
      [{
        "endpoint": "http://%%host%%:8080/metrics",
        "api_token": "ENC[dd/prod/custom/internal-api/token]",
        "tags": ["service:my-service", "env:prod"]
      }]
```

### 9.3 DogStatsD

DogStatsD accepts metrics over UDP 8125 without Agent-side authentication. Applications send
metrics directly to the Agent and do not need access to the Datadog API key. If an application
needs to call the Datadog API directly (post an event, create a monitor), it should fetch the
key via its own IAM role — not through the Datadog Agent:

```python
# Application code — DogStatsD needs no API key from the application
from datadog import statsd
statsd.gauge("my_app.queue_depth", queue.size(), tags=["env:prod", "service:my-app"])

# For direct Datadog API calls from the app — use application's own IAM role
import boto3
client = boto3.client("secretsmanager", region_name="us-east-1")
resp = client.get_secret_value(SecretId="dd/prod/agent/api_key")
dd_api_key = resp["SecretString"]
```

---

## 10. Service-by-Service Secret Mapping Reference

Single-source reference: secret handle → integration config fields → minimum
database/service permissions required. Use this when onboarding a new service or
auditing existing configuration.

### MySQL / RDS MySQL

**Secret:** `dd/prod/mysql/creds` → `{"username":"datadog","password":"..."}`

```yaml
# conf.d/mysql.d/conf.yaml
instances:
  - host: prod-mysql.cluster.us-east-1.rds.amazonaws.com
    port: 3306
    username: ENC[dd/prod/mysql/creds;username]
    password: ENC[dd/prod/mysql/creds;password]
    options:
      replication: false
    tags:
      - service:mysql
      - db_type:rds
      - env:prod
```

Minimum MySQL permissions:
```sql
CREATE USER 'datadog'@'%' IDENTIFIED BY '<password>';
GRANT REPLICATION CLIENT ON *.* TO 'datadog'@'%';
GRANT PROCESS ON *.* TO 'datadog'@'%';
GRANT SELECT ON performance_schema.* TO 'datadog'@'%';
```

### PostgreSQL / RDS PostgreSQL

**Secret:** `dd/prod/postgres/creds` → `{"username":"datadog","password":"..."}`

```yaml
# conf.d/postgres.d/conf.yaml
instances:
  - host: prod-pg.cluster.us-east-1.rds.amazonaws.com
    port: 5432
    username: ENC[dd/prod/postgres/creds;username]
    password: ENC[dd/prod/postgres/creds;password]
    dbname: prod_db
    ssl: require
    tags:
      - service:postgres
      - db_type:rds
      - env:prod
```

Minimum PostgreSQL permissions:
```sql
CREATE USER datadog WITH PASSWORD '<password>';
GRANT pg_monitor TO datadog;
GRANT SELECT ON pg_stat_database TO datadog;
```

### Redis / ElastiCache

**Secret:** `dd/prod/redis/password` → `"plain-auth-string"`

```yaml
# conf.d/redisdb.d/conf.yaml
instances:
  - host: prod-redis.cache.amazonaws.com
    port: 6379
    password: ENC[dd/prod/redis/password]
    tags:
      - service:redis
      - env:prod
```

### MongoDB / DocumentDB

**Secret:** `dd/prod/mongodb/creds` → `{"username":"datadog","password":"..."}`

```yaml
# conf.d/mongo.d/conf.yaml
instances:
  - hosts:
      - prod-mongo.internal:27017
    username: ENC[dd/prod/mongodb/creds;username]
    password: ENC[dd/prod/mongodb/creds;password]
    database: admin
    options:
      authSource: admin
    tags:
      - service:mongodb
      - env:prod
```

### SNMPv2c

**Secret:** `dd/prod/snmp/access_switches` → `"community-string"`

```yaml
community_string: ENC[dd/prod/snmp/access_switches]
```

### SNMPv3

**Secret:** `dd/prod/snmp/core_routers` → `{"auth_key":"...","priv_key":"..."}`

```yaml
authKey: ENC[dd/prod/snmp/core_routers;auth_key]
privKey: ENC[dd/prod/snmp/core_routers;priv_key]
```

### Agent-Level (datadog.yaml)

**Secrets:** `dd/prod/agent/api_key`, `dd/prod/agent/app_key` → plain strings

```yaml
api_key: ENC[dd/prod/agent/api_key]
app_key: ENC[dd/prod/agent/app_key]
```

---

## 11. IaC Provisioning Patterns (Tooling-Agnostic)

This section describes what needs to be provisioned and in what order, expressed as operations
rather than tool-specific code. Adapt these to Terraform, Pulumi, CloudFormation, or manual
AWS CLI as appropriate.

### 11.1 Provisioning Order and Dependencies

```
Phase 1 — Foundation (no dependencies)
  1a. Create KMS key per environment with automatic rotation enabled
  1b. Create IAM policies (SecretsRead + KMSDecrypt, scoped per environment)

Phase 2 — Identities (depends on Phase 1)
  2a. Create IAM roles (EC2 instance role, IRSA role, on-prem AssumeRole target)
  2b. Attach Phase 1 policies to Phase 1 roles
  2c. Create EC2 instance profiles wrapping the instance role
  2d. Create bootstrap IAM user (on-prem only) with AssumeRole-only policy

Phase 3 — Secrets (depends on Phase 1)
  3a. Create secrets in Secrets Manager with Phase 1 KMS key
  3b. Set initial secret values (via CI/CD variables — never hardcode)
  3c. Tag secrets with environment, service, and rotation metadata

Phase 4 — Compute binding (depends on Phase 2 + Phase 3)
  4a. Attach instance profiles to EC2 instances
  4b. Annotate EKS ServiceAccounts with IRSA role ARNs
  4c. Distribute bootstrap credentials to on-prem hosts via config management

Phase 5 — Agent configuration (depends on Phase 4)
  5a. Deploy datadog.yaml with secret_backend_type and ENC[] handles
  5b. Deploy integration conf.yaml files with ENC[] handles
  5c. Restart Agent and verify: sudo datadog-agent secret
```

### 11.2 Secret Value Management

Secret values (the actual passwords and API keys) must never appear in:

- IaC state files (Terraform state, CloudFormation templates in S3)
- Version-controlled files (`.tfvars`, Helm values, Ansible vars)
- CI/CD pipeline logs

Acceptable patterns for injecting secret values during provisioning:

```bash
# Option 1: CI/CD environment variables → AWS CLI at pipeline time
aws secretsmanager put-secret-value \
  --secret-id dd/prod/mysql/creds \
  --secret-string "{\"username\":\"datadog\",\"password\":\"${MYSQL_DATADOG_PASSWORD}\"}"
# MYSQL_DATADOG_PASSWORD sourced from GitHub Actions secret, GitLab CI variable, etc.

# Option 2: Read from an upstream secrets vault and pipe to AWS CLI
vault kv get -field=password secret/prod/mysql/datadog | \
  xargs -I{} aws secretsmanager put-secret-value \
    --secret-id dd/prod/mysql/creds \
    --secret-string "{\"username\":\"datadog\",\"password\":\"{}\"}"

# Option 3: Terraform with sensitive variable (value never in state in plaintext)
variable "mysql_datadog_password" {
  sensitive = true
}
resource "aws_secretsmanager_secret_version" "mysql" {
  secret_id     = aws_secretsmanager_secret.mysql.id
  secret_string = jsonencode({
    username = "datadog"
    password = var.mysql_datadog_password
  })
}
# Pass: terraform apply -var="mysql_datadog_password=${MYSQL_DATADOG_PASSWORD}"
```

### 11.3 State and Config File Security

| Artifact | Risk | Mitigation |
|---|---|---|
| Terraform state | Secret values visible in state | Use remote backend with SSE (S3+KMS); restrict state access to CI role only |
| Helm values files | ENC[] handles visible (safe) — no values | ENC[] is the handle, not the value; safe to commit |
| Ansible vars | Bootstrap key IDs visible if not vaulted | Use `ansible-vault encrypt_string` for any credential variable |
| `datadog.yaml` | ENC[] handles visible (safe) | ENC[] is safe to log and inspect |
| systemd drop-in | Bootstrap key in plaintext | Mode 0600, root-owned; rotate bootstrap key quarterly |

---

## 12. Secret Rotation Runbook

### 12.1 Datadog API Key (Zero-Downtime)

This is the only rotation that requires no Agent restart when `secret_refresh_interval` is set.

```bash
# 1. Create a new API key in Datadog Organization Settings

# 2. Update AWS Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id dd/prod/agent/api_key \
  --secret-string "new-api-key-value"

# 3. Wait for secret_refresh_interval (up to 3600s by default)
#    The Agent polls on this interval and reloads the key without restart

# 4. Verify the new key is active on a sample host
sudo datadog-agent status | grep -A5 "API Keys status"

# 5. Revoke the old API key in Datadog Organization Settings
# 6. Confirm no errors in: /var/log/datadog/agent.log
```

### 12.2 Database Password (Agent Restart Required)

```bash
# 1. Coordinate DBA to rotate the database user password

# 2. Update AWS Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id dd/prod/mysql/creds \
  --secret-string '{"username":"datadog","password":"new-password"}'

# 3. Restart Agent on affected hosts

#    EC2 / on-prem VMs:
sudo systemctl restart datadog-agent

#    EKS rolling restart (no downtime):
kubectl rollout restart daemonset/datadog-agent -n datadog
kubectl rollout status daemonset/datadog-agent -n datadog

# 4. Verify
sudo datadog-agent secret
sudo datadog-agent check mysql

# 5. Confirm integration checks are green in Datadog UI (Integrations > MySQL)
```

### 12.3 SNMP Credentials (Agent Restart Required)

```bash
# 1. Coordinate with network team — rotate credentials on devices first

# 2. Update AWS Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id dd/prod/snmp/core_routers \
  --secret-string '{"auth_key":"new-auth-passphrase","priv_key":"new-priv-passphrase"}'

# 3. Restart Agent on SNMP collector hosts only
#    Use rolling restart if multiple collector hosts exist
sudo systemctl restart datadog-agent

# 4. Verify
sudo datadog-agent check snmp
sudo datadog-agent secret

# 5. Confirm devices appear in Datadog Network Devices UI
```

### 12.4 Bootstrap IAM Key (On-Prem Hosts)

Rotate quarterly or immediately after any suspected exposure:

```bash
# 1. Create a new access key for the bootstrap IAM user
aws iam create-access-key --user-name dd-agent-bootstrap-dc1

# 2. Update systemd drop-in on all on-prem hosts with new key
#    (via config management tool or manual)
sudo vi /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf

# 3. Reload and restart Agent
sudo systemctl daemon-reload
sudo systemctl restart datadog-agent

# 4. Verify secret resolution still works
sudo datadog-agent secret

# 5. Delete the old access key
aws iam delete-access-key \
  --user-name dd-agent-bootstrap-dc1 \
  --access-key-id AKIAIOSFODNN7EXAMPLE_OLD
```

---

## 13. Validation and Smoke Testing

### 13.1 Post-Deployment Checklist

Run these checks after every Agent deployment or configuration change:

```bash
# 1. Verify all secrets resolve without errors
sudo datadog-agent secret

# 2. Full Agent health check
sudo datadog-agent status

# 3. Integration-specific checks
sudo datadog-agent check mysql
sudo datadog-agent check postgres
sudo datadog-agent check redisdb
sudo datadog-agent check snmp       # on collector hosts only

# 4. Confirm no plaintext credentials in logs
sudo grep -iE "password|api_key|auth_key|priv_key|secret" \
  /var/log/datadog/agent.log | grep -v 'ENC\['

# 5. Confirm APM intake is accepting traces (EC2/EKS)
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8126/v0.4/traces \
  -H "Content-Type: application/json" \
  -d '[[{"trace_id":1,"span_id":1,"name":"smoke","resource":"/smoke","service":"smoke-test","type":"web","start":0,"duration":1000000}]]'
# Expected response: 200

# 6. For on-prem hosts — confirm AssumeRole is working
aws sts get-caller-identity \
  --profile datadog-agent 2>/dev/null || \
  sudo -u dd-agent aws sts get-caller-identity
```

### 13.2 Common Failure Modes and Diagnosis

| Symptom | Likely Cause | Resolution |
|---|---|---|
| `sudo datadog-agent secret` shows `error` for a handle | Secret name typo, IAM permission missing, or KMS decrypt denied | Check CloudTrail for `AccessDeniedException` on the secret ARN |
| Integration check shows `CRITICAL` immediately after deployment | Secret resolved but credentials wrong at DB level | Check DB-side user permissions; test connection manually |
| `%1 is not a valid Win32 application` (Windows) | Backend script is `.py` or `.ps1`, not a `.exe` | Compile to Win32 binary or use `python.exe` as the command |
| SNMP check returns no devices | Network reachability or wrong credentials | Run `snmpwalk` from collector host to verify reachability before Agent check |
| `AccessDeniedException` in Agent logs on on-prem host | STS AssumeRole failed — check bootstrap key validity and external ID | Run `aws sts assume-role` manually from the host to isolate |
| ENC[] handle silently ignored (value is literal `ENC[...]`) | ENC[] is not the entire YAML value — partial embedding is not supported | Ensure the field value is `ENC[handle]` with no surrounding text |
| Cluster Agent cannot resolve secrets | Agent version < 7.77 or missing IRSA annotation on Cluster Agent ServiceAccount | Upgrade to 7.77+ and verify IRSA annotation on both ServiceAccounts |

### 13.3 EKS Post-Sync Smoke Test (Argo CD Hook)

```yaml
# argocd/datadog-smoke-test.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: datadog-secret-smoke-test
  namespace: datadog
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
spec:
  template:
    spec:
      serviceAccountName: datadog-agent
      containers:
        - name: smoke-test
          image: gcr.io/datadoghq/agent:7.77.0
          command:
            - /bin/bash
            - -c
            - |
              echo "=== Secret Resolution Check ==="
              agent secret
              [ $? -ne 0 ] && echo "FAILED: secret resolution" && exit 1

              echo "=== Agent Status Check ==="
              agent status
              [ $? -ne 0 ] && echo "FAILED: agent status" && exit 1

              echo "=== All checks passed ==="
      restartPolicy: Never
  backoffLimit: 1
```

---

## References

- [Datadog Secrets Management Documentation](https://docs.datadoghq.com/agent/configuration/secrets-management/)
- [Datadog Network Device Monitoring](https://docs.datadoghq.com/network_monitoring/devices/)
- [Datadog SNMP Integration](https://docs.datadoghq.com/integrations/snmp/)
- [Datadog Custom Checks](https://docs.datadoghq.com/developers/custom_checks/write_agent_based_check/)
- [Datadog Agent Autodiscovery](https://docs.datadoghq.com/containers/kubernetes/integrations/)
