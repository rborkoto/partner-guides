# Datadog Secrets Management Strategy for Multi-Cloud Environments (v0.9)

> **Note:** This is not meant to replace any official Datadog documentation. Please refer to [docs.datadoghq.com](https://docs.datadoghq.com) for the latest updates and changes.
>
> **Changelog from v0.8:** Corrected Agent version matrix for native backends (7.70 / 7.74 / 7.76 / 7.77+). Updated `datadog-secret-backend` status (archived March 2026 — migrate to native `secret_backend_type`). Corrected on-premises AWS authentication options (static credentials are not the only option). Updated CyberArk product names (PAM Self-Hosted, Privilege Cloud, Secrets Manager SaaS/Self-Hosted). Added Azure Key Vault and GCP Secret Manager as first-class Approach 2 options alongside AWS. Added Windows implementation guidance. Added partner best practices section. Expanded comparison table.

---

## What Is Covered

Ways to manage Datadog secrets across cloud and on-premises environments. This guide covers three approaches and will be continuously updated — HashiCorp Vault will be added in a future revision.

---

## Solution Options

This document outlines three approaches to secrets management, each with different trade-offs in complexity, tooling requirements, and operational overhead.

---

## How Datadog Secrets Management Works

All three approaches use the same Datadog Agent mechanism. The Agent calls a backend executable at startup, passing secret handles via stdin and receiving plaintext values via stdout. Secrets are loaded in memory only and never written to disk.

### Wire Protocol

The Datadog Agent communicates with the backend executable using a JSON protocol.

**Agent sends to the backend via stdin:**

```json
{
  "version": "1.0",
  "secrets": ["db.password", "dd.api_key"]
}
```

**Backend must return via stdout:**

```json
{
  "db.password": { "value": "mysecretpassword", "error": null },
  "dd.api_key":  { "value": "abc123def456",    "error": null }
}
```

> **Important:** If `error` is non-null for any handle, the integration config referencing that handle is dropped entirely for the lifetime of that resolution cycle. Implement per-secret error handling — do not call `sys.exit(1)` on a single failure or unrelated integrations will also stop working.

### Integration Configuration

Integration configs reference secrets using `ENC[]` placeholders:

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[db.password]
```

The Agent resolves `ENC[db.password]` at startup by calling the configured backend. Two critical constraints apply:

- `ENC[]` must be the **entire YAML value** — partial embedding like `"prefix-ENC[handle]"` is silently ignored.
- **Secrets are always treated as strings.** You cannot pass booleans or integers through ENC[].

### Agent Version Requirements

| Feature | Minimum Agent Version |
|---|---|
| Custom executable backend (`secret_backend_command`) | 6.12+ (GA for Linux/Windows) |
| Native backend (`secret_backend_type`) — AWS Secrets Manager, AWS SSM, Azure Key Vault, HashiCorp Vault | **7.70+** |
| Native backend — GCP Secret Manager | **7.74+** |
| FIPS-compliant native backends | **7.76+** |
| Bundled `secret-generic-connector` (replaces standalone binary); Cluster Agent native secrets | **7.77+** |

> **Note on `datadog-secret-backend` standalone binary:** The [DataDog/datadog-secret-backend](https://github.com/DataDog/datadog-secret-backend) repository was **archived on March 2, 2026**. Existing installations continue to work with newer Agents, but Datadog strongly recommends migrating to the native `secret_backend_type` configuration (Agent 7.70+). The standalone binary is **not FIPS-compliant**. For new deployments, use the bundled connector.

### Key `datadog.yaml` Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `secret_backend_command` | unset | Path to custom executable (legacy) |
| `secret_backend_arguments` | `[]` | Arguments passed to the executable |
| `secret_backend_timeout` | 30 seconds | Per-invocation timeout |
| `secret_backend_output_max_size` | 1,048,576 bytes | Combined stdout+stderr buffer |
| `secret_backend_type` | unset | Native backend selector (7.70+) |
| `secret_backend_config` | unset | Backend-specific config block (7.70+) |
| `secret_backend_command_allow_group_exec_perm` | `false` | Allow group-exec bit on executable |
| `secret_backend_remove_trailing_line_break` | `false` | Strip trailing newline (7.45+) |
| `secret_refresh_interval` | `0` | Live API/APP key refresh in seconds (7.67+) |

Valid values for `secret_backend_type`: `aws.secrets`, `aws.ssm`, `azure.keyvault`, `gcp.secretmanager`, `hashicorp.vault`, `k8s.secrets`, `docker.secrets`, `file.text`, `file.json`, `file.yaml`.

### Verifying Secret Resolution

```bash
sudo datadog-agent secret
```

Output includes the file permission/ownership check and a list of all resolved handles. This is the canonical troubleshooting command — run it after any configuration change before declaring a deployment successful.

---

## 1) Platform-Native Secret Management (No External Tools)

![Approach 1: Platform-Native](https://github.com/user-attachments/assets/a37acde0-3697-4b8a-8685-d8cd4cfe53d7)

This approach uses no external secrets management tools. It relies on native OS capabilities, Kubernetes features, and your existing deployment pipeline.

### Goal

- No secrets in code or repositories
- Runtime injection of secrets
- Least-privilege access controls
- Repeatable rotation process, even if not fully automated

### How It Works

#### A) Store Secrets Outside Code

Remove all keys and passwords from scripts, configuration files, Helm values, Terraform variables, and any version-controlled artifacts. Store secrets in platform-native mechanisms instead.

**Kubernetes:** Store secrets in Kubernetes Secrets objects. Use separate namespaces per environment. Reference secrets via environment variables or volume mounts.

**Virtual Machines:** Store secrets in root-owned files with strict permissions (mode `0600`). Use systemd environment files for service configuration. Place secret files in protected directories like `/etc/datadog-agent/secrets/`.

**SNMP Collectors:** Use the same mechanism as the collector host — Kubernetes Secrets for containerized collectors, root-owned files for VM-based collectors.

#### B) Encrypt at Rest (Native)

**Kubernetes:** Enable etcd encryption at rest using Kubernetes native encryption providers. Configure RBAC policies to restrict Secret access to only the Datadog Agent service account. Use network policies to limit access to etcd.

**Virtual Machines (Linux):** Store secret files on encrypted disks. For cloud VMs, enable cloud disk encryption (AWS EBS, Azure Disk Encryption, GCP persistent disk encryption). Restrict file access to `dd-agent` or root only. Use filesystem-level encryption where available (LUKS on Linux, BitLocker on Windows).

#### C) Inject at Runtime

**Kubernetes:** Mount Kubernetes Secrets as files into the Datadog Agent pod using volume mounts, or inject as environment variables. Ensure secrets are never logged or exposed in pod specifications.

**Virtual Machines:** Use systemd drop-in environment files read at service startup, or use the Datadog Agent Secrets Management feature with ENC[] placeholders and a local backend script.

#### D) Rotation Process

Implement a structured rotation process even without full automation:

- **Kubernetes:** Update the Secret object and perform a rolling restart of the Agent DaemonSet.
- **VMs:** Update the secret file and restart the `datadog-agent` service.
- Maintain a rotation schedule and runbook in your documentation.
- Maintain audit evidence from deployment logs.

> **Important:** The Agent does not hot-reload arbitrary integration credentials without a restart. The `secret_refresh_interval` parameter (Agent 7.67+) applies primarily to the Datadog API key and APP key, not to integration credentials such as database passwords. Design rotation procedures to include an Agent restart.

### Prerequisites

**Kubernetes:** Kubernetes 1.13+, RBAC enabled, cluster-admin access for etcd encryption configuration, `kubectl` access to manage Secrets.

**Virtual Machines:** Root/administrator access, ability to enable disk encryption, systemd or Windows Service Manager, Datadog Agent 7.70+ for native secrets support.

**General:** CI/CD pipeline or configuration management tool (Ansible, Puppet, Chef). Process for secret rotation and documentation.

**Network Connectivity:**

| Endpoint | Purpose | Protocol |
|---|---|---|
| `*.datadoghq.com` | Agent metrics, APM, logs | HTTPS (443) |
| `intake.logs.datadoghq.com` | Log collection | HTTPS (443) |

### Setup Guidance

#### Step 1: Remove Hardcoded Secrets

Audit all configuration files, scripts, and deployment manifests. Identify and document all hardcoded API keys, passwords, and credentials.

#### Step 2: Create Secret Storage

**Kubernetes:**

```yaml
# k8s-datadog-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: datadog-secrets
  namespace: datadog
type: Opaque
stringData:
  DD_API_KEY: "your-datadog-api-key"
  mysql_password: "your-mysql-password"
```

```bash
kubectl apply -f k8s-datadog-secret.yaml
```

**Helm — reference the existing secret:**

```yaml
# values.yaml
datadog:
  apiKeyExistingSecret: datadog-secrets
  apiKeyExistingSecretKey: DD_API_KEY
  volumes:
    - name: integration-secrets
      secret:
        secretName: datadog-secrets
  volumeMounts:
    - name: integration-secrets
      mountPath: /etc/datadog-agent/secrets
      readOnly: true
```

**VMs (Linux):**

```bash
sudo mkdir -p /etc/datadog-agent/secrets
sudo touch /etc/datadog-agent/secrets/secrets.json
sudo chmod 700 /etc/datadog-agent/secrets
sudo chmod 600 /etc/datadog-agent/secrets/secrets.json
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/secrets.json
```

```json
{
  "dd.api_key": "your-datadog-api-key",
  "db.password": "your-mysql-password"
}
```

**VMs (Windows):** The backend executable must be a valid Win32 application (`.exe`). Scripts such as `.ps1`, `.py`, and `.bat` will fail with `%1 is not a valid Win32 application`. Compile to a Go binary, use a code-signed .NET executable, or use ps2exe to wrap PowerShell. Set the ACL on the binary to allow only `LOCAL_SYSTEM`, `BUILTIN\Administrators`, and the Agent user (default `ddagentuser`), with inheritance disabled.

```powershell
# Set ACL on Windows — run as Administrator
$path = "C:\ProgramData\Datadog\secrets\fetch_secrets.exe"
$acl = Get-Acl $path
$acl.SetAccessRuleProtection($true, $false)   # disable inheritance, remove inherited entries
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","ReadAndExecute","Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
$rule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("ddagentuser","ReadAndExecute","Allow")
$acl.SetAccessRule($rule1); $acl.SetAccessRule($rule2); $acl.SetAccessRule($rule3)
Set-Acl $path $acl
```

#### Step 3: Backend Script (Linux VM Example)

```python
#!/usr/bin/env python3
# /etc/datadog-agent/secrets/fetch_secrets.py
import json, sys

SECRETS_FILE = "/etc/datadog-agent/secrets/secrets.json"

def main():
    payload = json.load(sys.stdin)
    with open(SECRETS_FILE) as f:
        store = json.load(f)
    result = {}
    for handle in payload.get("secrets", []):
        if handle in store:
            result[handle] = {"value": store[handle], "error": None}
        else:
            # Return per-secret error — do NOT exit(1) as that drops all handles
            result[handle] = {"value": None, "error": f"handle '{handle}' not found"}
            print(f"Error: secret '{handle}' not found", file=sys.stderr)
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

> **SELinux note (RHEL/Rocky):** Custom paths outside `/etc/datadog-agent/` may require a context label:
> ```bash
> sudo chcon -t bin_t /etc/datadog-agent/secrets/fetch_secrets.py
> ```

#### Step 4: Configure the Datadog Agent

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[dd.api_key]

secret_backend_command: /etc/datadog-agent/secrets/fetch_secrets.py
secret_backend_timeout: 30
secret_backend_output_max_size: 1048576
```

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[db.password]
```

#### Step 5: Rotation

**VMs:**

```bash
sudo vi /etc/datadog-agent/secrets/secrets.json
sudo systemctl restart datadog-agent
sudo datadog-agent secret   # verify resolution
```

**Kubernetes:**

```bash
kubectl create secret generic datadog-secrets \
  --from-literal=DD_API_KEY=new-api-key \
  --from-literal=mysql_password=new-password \
  -n datadog --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart daemonset/datadog-agent -n datadog
```

#### Step 6: Verify

```bash
sudo datadog-agent secret
sudo datadog-agent status
```

Check that secrets are not present in logs or configuration dumps. Review access logs to confirm only authorized processes accessed secrets.

---

## 2) Cloud-Native Secret Management (AWS / Azure / GCP)

This approach uses managed cloud services for secret storage and encryption. While the diagrams below show the AWS pattern, **Azure Key Vault and GCP Secret Manager are first-class options** with native Agent support at parity (subject to the version matrix above).

![Approach 2: Cloud-Native](https://github.com/user-attachments/assets/1eccb3e9-1bd7-407a-afaa-886079674db6)

### Goal

- Centralized secret management within your cloud provider
- Automated secret rotation
- Versioning and audit trails
- Identity-based access using cloud-native roles (no long-lived credentials on the host)
- Integration with cloud services and workloads

### 2a) AWS Secrets Manager + KMS

#### How It Works

**Storage and encryption:** Secrets are stored in AWS Secrets Manager, encrypted at rest using AWS KMS customer master keys. Secrets can be structured (JSON) or plaintext with version history.

**Access control:** IAM policies attached to IAM roles control access. For EC2, use instance profiles. For EKS pods, use IAM Roles for Service Accounts (IRSA). For Lambda, use execution roles.

**On-premises authentication:** Instance profiles are unavailable outside AWS. Datadog uses the AWS SDK Default Credential Provider Chain, which means multiple options work — not just static keys:

- **STS AssumeRole** (recommended): Use a low-privilege bootstrap IAM key to assume a role with Secrets Manager and KMS permissions. Supports external ID for cross-account trust.
- **Static credentials** via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables or `~/.aws/credentials`.
- **Named profiles** via `aws_profile` in `secret_backend_config` referencing a configured `~/.aws/config` profile.
- **IAM Roles Anywhere**: X.509-certificate-based federation via `credential_process` pointing at `aws_signing_helper`. Works transparently through the SDK credential chain but is not directly documented by Datadog.
- **AWS SSO / IAM Identity Center**: Works via `aws_profile` referencing an `sso_session` block in `~/.aws/config`.

**Rotation:** Secrets Manager supports automatic rotation via Lambda functions. Previous versions remain available for rollback.

**Datadog Agent integration:** Use the native `secret_backend_type: aws.secrets` (Agent 7.70+) or a custom Python/shell script as `secret_backend_command`.

#### Prerequisites

- AWS account with IAM, Secrets Manager, and KMS access.
- IAM roles for EC2 instance profiles, EKS IRSA, or equivalent on-prem credential.
- Outbound HTTPS (443) to AWS service endpoints.

**Network Connectivity:**

| Endpoint | Purpose | Protocol |
|---|---|---|
| `secretsmanager.{region}.amazonaws.com` | Secret retrieval | HTTPS (443) |
| `kms.{region}.amazonaws.com` | KMS decrypt | HTTPS (443) |
| `sts.{region}.amazonaws.com` | IAM role assumption | HTTPS (443) |
| `169.254.169.254` | EC2 instance metadata (IMDSv2) | HTTP (80) |
| `*.datadoghq.com` | Agent telemetry | HTTPS (443) |

> **IMDSv2 note:** IMDSv2 is the default for most new EC2 instance types. The AWS SDK handles token retrieval transparently — no Datadog-specific configuration is needed.

For private networking, configure VPC endpoints for Secrets Manager, KMS, and STS.

#### Setup Guidance

**Step 1: Create KMS Key and Store Secrets**

```bash
aws kms create-key \
  --description "Datadog secrets encryption key" \
  --key-usage ENCRYPT_DECRYPT

aws secretsmanager create-secret \
  --name "datadog/api_key" \
  --secret-string "your-datadog-api-key" \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/your-key-id"

aws secretsmanager create-secret \
  --name "datadog/mysql" \
  --secret-string '{"password":"your-mysql-password","username":"datadog"}' \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
```

> **Fleet quota guidance:** Pack related credentials into a single JSON secret and use `;secretKey` extraction syntax (e.g., `ENC[datadog/mysql;password]`) to reduce `GetSecretValue` call volume. The default quota is 5,000 requests/second per account — a large Agent fleet starting simultaneously can hit this during a thundering herd.

**Step 2: Create IAM Role and Policy**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsRetrieval",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:datadog/*"
    },
    {
      "Sid": "AllowKMSDecrypt",
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
    }
  ]
}
```

Attach this policy to:

- **EC2:** IAM role → instance profile → attached to EC2 instances running Datadog Agent.
- **EKS:** IAM role → annotated on Kubernetes ServiceAccount (IRSA).
- **On-prem:** IAM user (static credentials) or IAM role (via STS AssumeRole or IAM Roles Anywhere).

**Step 3: Configure the Datadog Agent**

**Native backend (Agent 7.70+) — EC2 with instance profile (no credentials in config):**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[datadog/api_key]

secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
```

**EKS with IRSA — annotate the ServiceAccount:**

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: datadog-agent
  namespace: datadog
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/datadog-agent-role
```

```yaml
# datadog.yaml (no credentials — IRSA handles auth automatically)
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
```

**On-premises with STS AssumeRole (recommended over static keys):**

```yaml
# /etc/datadog-agent/datadog.yaml
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_role_arn: "arn:aws:iam::123456789012:role/datadog-onprem-role"
    aws_external_id: "unique-external-id"         # optional but recommended
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"      # bootstrap key only — least privilege
    aws_secret_access_key: "wJalrXUtnFEMI..."
```

**On-premises with static credentials via systemd (keeps credentials out of datadog.yaml):**

```ini
# /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
[Service]
Environment="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
Environment="AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI..."
Environment="AWS_DEFAULT_REGION=us-east-1"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart datadog-agent
```

**Reference secrets in integration configs:**

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[datadog/mysql;password]   # JSON sub-key extraction using ;
```

**Step 4: Verify**

```bash
sudo datadog-agent secret
sudo datadog-agent status
```

Monitor CloudTrail for `GetSecretValue` calls. Verify no secrets appear in `datadog-agent status` output or logs.

**Step 5: Configure Rotation (Optional)**

Create a Lambda rotation function via Secrets Manager. Test rotation in non-production. Monitor rotation success and failures via CloudWatch.

---

### 2b) Azure Key Vault

Azure Key Vault is a first-class native backend in Agent 7.70+.

#### How It Works

**Storage:** Secrets, keys, and certificates are stored in Azure Key Vault. Two tiers are available: Standard (software-backed) and Premium (HSM-backed).

**Access control:** Azure RBAC and Key Vault access policies control access. For Azure VMs, use system-assigned or user-assigned **Managed Identities** (strongly recommended by Datadog). For AKS, use **AKS Workload Identity**.

**Datadog Agent integration:** Use `secret_backend_type: azure.keyvault` (Agent 7.70+). Authentication uses Azure's `DefaultAzureCredential` chain — Managed Identity, Workload Identity, Service Principal (via environment variables), and Azure CLI all work transparently.

#### Setup Guidance

**Create a Key Vault and store secrets:**

```bash
az keyvault create --name "datadog-keyvault" --resource-group "myRG" --location "eastus"

az keyvault secret set --vault-name "datadog-keyvault" \
  --name "dd-api-key" --value "your-datadog-api-key"

az keyvault secret set --vault-name "datadog-keyvault" \
  --name "mysql-password" --value "your-mysql-password"
```

**Grant the Managed Identity access:**

```bash
# Assign Key Vault Secrets User role to the VM's managed identity
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "<managed-identity-principal-id>" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/datadog-keyvault"
```

**Configure the Datadog Agent (VM with Managed Identity):**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[dd-api-key]

secret_backend_type: azure.keyvault
secret_backend_config:
  azure_keyvault:
    vault_url: "https://datadog-keyvault.vault.azure.net/"
```

**AKS Workload Identity — annotate the Datadog ServiceAccount:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: datadog-agent
  namespace: datadog
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
  labels:
    azure.workload.identity/use: "true"
```

**Reference secrets in integration configs:**

```yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[mysql-password]
```

---

### 2c) GCP Secret Manager

GCP Secret Manager is a native backend in Agent 7.74+.

#### How It Works

**Storage:** Secrets are stored in GCP Secret Manager with versioning and IAM-based access control.

**Access control:** Use GCE VM service accounts or GKE Workload Identity. The Datadog Agent service account needs the `secretmanager.versions.access` permission (typically via the predefined role `roles/secretmanager.secretAccessor`).

**Datadog Agent integration:** Use `secret_backend_type: gcp.secretmanager` (Agent 7.74+). Authentication uses Application Default Credentials (ADC) — no credentials need to be configured explicitly when running on GCE or GKE with correct service account bindings.

#### Setup Guidance

**Create secrets:**

```bash
gcloud secrets create dd-api-key --replication-policy="automatic"
echo -n "your-datadog-api-key" | gcloud secrets versions add dd-api-key --data-file=-

gcloud secrets create mysql-password --replication-policy="automatic"
echo -n "your-mysql-password" | gcloud secrets versions add mysql-password --data-file=-
```

**Grant access to the GCE service account:**

```bash
gcloud secrets add-iam-policy-binding dd-api-key \
  --member="serviceAccount:datadog-sa@your-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**GKE Workload Identity — annotate the Datadog ServiceAccount:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: datadog-agent
  namespace: datadog
  annotations:
    iam.gke.io/gcp-service-account: "datadog-sa@your-project.iam.gserviceaccount.com"
```

**Configure the Datadog Agent:**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[dd-api-key]

secret_backend_type: gcp.secretmanager
secret_backend_config:
  gcp_session:
    project_id: "your-gcp-project"
```

**Reference a specific version or JSON sub-key:**

```yaml
# Latest version (default)
password: ENC[mysql-password]

# Specific version
password: ENC[mysql-password;key;3]
```

---

## 3) CyberArk Approach (Centralized Hybrid Secrets Management)

This approach uses CyberArk as a centralized secrets management platform across all cloud providers and on-premises environments. It provides a single control plane for secret governance, rotation, and audit across the entire hybrid infrastructure.

![Approach 3: CyberArk](https://github.com/user-attachments/assets/124c265c-8265-4543-bc29-b6fd3ee6ba5c)

> **Product naming note:** CyberArk has updated product names as of 2025. Use the following current names:
> - **CyberArk Privileged Access Manager (PAM) Self-Hosted** (current version 15.0) — formerly "Privileged Access Security" / "PAS"
> - **CyberArk Privilege Cloud** — the SaaS PAM offering
> - **CyberArk Secrets Manager, Self-Hosted** (current version 13.7) — formerly "Conjur Enterprise"
> - **CyberArk Secrets Manager, SaaS** — formerly "Conjur Cloud"
> - **Conjur Open Source** — retains the Conjur name; actively maintained
>
> "CyberArk Identity Security Platform" is the umbrella brand, not a 1:1 rename of PAS.

### Goal

- Centralized secret management across AWS, Azure, GCP, and on-premises
- Unified governance and compliance reporting
- Automated secret rotation with centralized policies
- Identity-based access using cloud-native identities
- Comprehensive audit trail

### How It Works

**Important:** There is **no native CyberArk backend** in `secret_backend_type` or the bundled `secret-generic-connector`. The CyberArk Marketplace integrations for Datadog ingest CyberArk telemetry **into** Datadog — they do not retrieve secrets **out** to the Agent.

Partners have two integration paths:

1. **Custom executable** that calls the CyberArk Central Credential Provider (CCP) AIMWebService API and implements the Datadog secret backend protocol.
2. **CyberArk Secrets Provider for Kubernetes** (`cyberark/secrets-provider-for-k8s`) to populate native Kubernetes Secrets, then use the Agent's `k8s.secrets` or `readsecret_multiple_providers.sh` to read them.

**Access control:** Access is controlled via CyberArk safes and policies. Authentication uses platform identity:

- AWS: IAM roles via CyberArk AWS integration
- Azure: Managed Identities via CyberArk Azure integration
- GCP: Service Accounts via CyberArk GCP integration
- On-premises: LDAP, Active Directory, or client certificates (mTLS)

**Rotation:** CyberArk provides centralized automated rotation via Privileged Access Manager. For Kubernetes, only **sidecar mode** (as opposed to init container mode) in the Secrets Provider supports continuous rotation without pod restart.

**Audit:** All access attempts and secret retrievals are logged centrally in CyberArk PAM. Enable CyberArk audit forwarding to Datadog Cloud SIEM for unified visibility.

### Prerequisites

- CyberArk PAM Self-Hosted or Privilege Cloud deployed and configured
- CyberArk license and support agreement
- CCP (Central Credential Provider) accessible from Datadog Agent hosts (HTTPS 443)
- Platform identities configured and registered in CyberArk safes
- Datadog Agent 6.12+ (custom executable path) or 7.70+ (if using native K8s Secrets integration)

**Network Connectivity:**

| Endpoint | Purpose | Protocol |
|---|---|---|
| CyberArk CCP endpoint | Secret retrieval via AIMWebService | HTTPS (443) |
| CyberArk Conjur / Secrets Manager endpoint (K8s) | Secrets Provider | HTTPS (443) |
| `sts.{region}.amazonaws.com` (AWS only) | IAM role assumption | HTTPS (443) |
| `169.254.169.254` (cloud VMs) | Instance metadata | HTTP (80) |
| `*.datadoghq.com` | Agent telemetry | HTTPS (443) |

### Setup Guidance

**Step 1: Deploy and Configure CyberArk**

Deploy CyberArk PAM Self-Hosted or configure Privilege Cloud. Set up high availability and backup procedures. Configure network connectivity from all target platforms to the CCP endpoint.

**Step 2: Create Safes and Policies**

Organize secrets using a Safe-per-environment convention:

```
Safe: DatadogProd
  └── datadog-api-key
  └── mysql-password
  └── snmp-community-string

Safe: DatadogDev
  └── datadog-api-key
  └── mysql-password
```

Grant your platform identities (IAM role ARN, Managed Identity, AD account) access to the appropriate Safe via CyberArk PVWA access control policies.

**Step 3: Configure Platform Integrations**

Set up CyberArk integrations for AWS (IAM role authentication), Azure (Managed Identity), GCP (Service Account), and on-premises (LDAP/AD or certificates). Configure and verify CCP authentication on a test host before fleet deployment.

**Step 4: Install Platform Components**

- **VMs:** Install CyberArk Credential Provider on Datadog Agent hosts.
- **Kubernetes:** Deploy `cyberark/secrets-provider-for-k8s` as an init container or sidecar.

**Step 5: Create the Backend Script (VMs)**

The CCP AIMWebService endpoint format is: `https://<CCP-host>/AIMWebService/api/Accounts?AppID=<app>&Safe=<safe>&Object=<obj>`.

```python
#!/usr/bin/env python3
# /etc/datadog-agent/secrets/fetch_secrets.py
import json, sys, requests

CYBERARK_URL = "https://cyberark.internal.example.com"
APP_ID = "DatadogAgent"
CERT = ("/etc/datadog-agent/secrets/client.crt",
        "/etc/datadog-agent/secrets/client.key")
CA_BUNDLE = "/etc/ssl/certs/ca-bundle.crt"

def get_secret(handle):
    # Handle format: "SafeName/ObjectName"
    parts = handle.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid handle format '{handle}'. Expected 'SafeName/ObjectName'")
    safe, obj = parts
    resp = requests.get(
        f"{CYBERARK_URL}/AIMWebService/api/Accounts",
        params={"AppID": APP_ID, "Safe": safe, "Object": obj},
        cert=CERT,
        verify=CA_BUNDLE,
        timeout=10   # Keep below secret_backend_timeout (30s default)
    )
    resp.raise_for_status()
    return resp.json()["Content"]

def main():
    payload = json.load(sys.stdin)
    result = {}
    for handle in payload.get("secrets", []):
        try:
            result[handle] = {"value": get_secret(handle), "error": None}
        except Exception as e:
            # Per-secret error — do NOT exit(1)
            result[handle] = {"value": None, "error": str(e)}
            print(f"Error retrieving '{handle}': {e}", file=sys.stderr)
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

**Step 6: Configure the Datadog Agent (VMs)**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[DatadogProd/datadog-api-key]

secret_backend_command: /etc/datadog-agent/secrets/fetch_secrets.py
secret_backend_timeout: 30
secret_backend_output_max_size: 1048576
```

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[DatadogProd/mysql-password]
```

**Step 7: Kubernetes with Secrets Provider**

Deploy the CyberArk Secrets Provider as an init container to populate Kubernetes Secrets, which the Datadog Agent reads via the standard K8s Secrets mechanism. Use sidecar mode if continuous rotation without pod restart is required.

```yaml
# datadog-agent deployment excerpt
spec:
  template:
    spec:
      serviceAccountName: datadog-agent
      initContainers:
        - name: cyberark-secrets-provider
          image: cyberark/secrets-provider-for-k8s:latest
          env:
            - name: CONJUR_AUTHN_LOGIN
              value: "host/datadog/datadog-agent"
            - name: CONJUR_APPLIANCE_URL
              value: "https://conjur.internal.example.com"
            - name: K8S_SECRETS
              value: "datadog-secrets"
          volumeMounts:
            - name: podinfo
              mountPath: /etc/conjur/podinfo
      containers:
        - name: datadog-agent
          image: gcr.io/datadoghq/agent:latest
          envFrom:
            - secretRef:
                name: datadog-secrets   # Populated by init container
```

**Step 8: Verify and Test**

```bash
# Test backend script directly before configuring the Agent
echo '{"version": "1.0", "secrets": ["DatadogProd/datadog-api-key"]}' \
  | sudo -u dd-agent /etc/datadog-agent/secrets/fetch_secrets.py

# After Agent configuration
sudo datadog-agent secret
sudo datadog-agent status
```

Review CyberArk PAM audit logs. Monitor for failed authentication attempts. Set up alerts for rotation failures. Forward CyberArk audit events to Datadog Cloud SIEM.

---

## Partner Best Practices

### Secret Handle Naming

Datadog does not enforce a naming convention; partners should define and document one per engagement. A recommended pattern:

```
<environment>-<application>-<component>-<credential>
```

Example: `prod-payments-postgres-password`

This produces readable output in `datadog-agent secret` and maps cleanly to safe/object hierarchies in CyberArk or path hierarchies in Secrets Manager.

**Delimiter reference by backend:**

| Backend | ENC[] sub-key syntax | Example |
|---|---|---|
| AWS Secrets Manager (JSON secret) | `ENC[secretId;jsonKey]` | `ENC[datadog/mysql;password]` |
| GCP Secret Manager (versioned) | `ENC[secret-name;key;version]` | `ENC[mysql-secret;password;3]` |
| Kubernetes Secrets | `ENC[k8s_secret@ns/secret/key]` | `ENC[k8s_secret@datadog/secrets/password]` |
| CyberArk CCP (custom script) | `ENC[Safe/ObjectName]` | `ENC[DatadogProd/mysql-password]` |

### Error Handling in Backend Scripts

- Implement retry-with-backoff **inside** the backend — the Agent does not retry within a single resolution call.
- Keep stderr minimal — it shares the 1 MiB output buffer with stdout. Noisy stderr can starve a valid response.
- Set internal HTTP/SDK timeouts below the Agent's `secret_backend_timeout` (default 30 seconds). For cloud APIs, use 10–15 seconds.
- Never call `sys.exit(1)` on a single-secret failure. Return `{"value": null, "error": "..."}` for failed handles and continue. This ensures other integrations remain functional.
- For fleets larger than 1,000 Agents, increase `secret_backend_output_max_size` to 4–8 MiB.

### Secret Rotation Reality

**The Agent does not hot-reload arbitrary integration credentials without a restart.** Plan rotation procedures accordingly:

| Secret type | Rotation method |
|---|---|
| Datadog API key / APP key | `secret_refresh_interval` in `datadog.yaml` (Agent 7.67+) — no restart required |
| All integration credentials (DB passwords, SNMP, etc.) | Agent restart or Autodiscovery template republish required |
| Kubernetes-mounted secrets | Rolling restart of Agent DaemonSet after updating Secret object |

### Security Hardening

**Linux:** Disable swap (`swapoff -a`) on hosts running Agents with sensitive credentials. Restrict core dumps (`ulimit -c 0`). Add custom secret patterns to `scrubber.additional_keys` in `datadog.yaml` to prevent accidental log exposure.

**Windows:** Code-sign all backend executables — unsigned `.exe` files may be blocked by Defender or AppLocker. Compile with Go or .NET for native Win32 compliance. Automate ACL configuration in your deployment tooling (Ansible, Puppet, or PowerShell DSC).

**Kubernetes:** Prefer per-namespace `Role`/`RoleBinding` over `enableGlobalPermissions: true`. Scope `secret_allowed_k8s_namespace` to explicit namespaces rather than wildcard access.

### Audit and Observability

Datadog produces no first-class audit trail for secret fetch events — audit must happen at the backend:

- **AWS:** Enable CloudTrail and monitor `secretsmanager:GetSecretValue` calls.
- **Azure:** Enable Key Vault diagnostic settings and stream to Log Analytics or Datadog.
- **GCP:** Enable Cloud Audit Logs for Secret Manager and export to Datadog.
- **CyberArk:** Forward PAM audit events to Datadog Cloud SIEM.

Alert on anomalies: unexpected access from new source IPs, access outside rotation windows, repeated failures.

### FIPS Compliance

For FedRAMP, FIPS 140-2/140-3, or government deployments:

- The **legacy `datadog-secret-backend` standalone binary is not FIPS-compliant**.
- FIPS-compliant native secrets require **Agent 7.76+** for FIPS-mode support and **Agent 7.77+** for the bundled `secret-generic-connector`.
- Custom Python backends are not FIPS-compliant unless compiled against a FIPS-validated Python build with FIPS-validated cryptographic modules.

---

## Comparison and Decision Guide

| Feature | Approach 1: Platform-Native | Approach 2: Cloud-Native (AWS / Azure / GCP) | Approach 3: CyberArk |
|---|---|---|---|
| **External tooling** | None | Cloud provider account | CyberArk license + deployment |
| **Min Agent version** | 7.70+ (native) or 6.12+ (custom exe) | 7.70+ (AWS/Azure), 7.74+ (GCP) | 6.12+ |
| **Multi-cloud support** | Yes (per-platform storage) | Limited (native backends are provider-specific) | Yes (centralized) |
| **Automatic rotation** | Manual / CI-CD driven | Yes (Lambda, Azure Key Vault rotation, GCP rotation) | Yes (PAM centralized) |
| **Audit trail** | Deployment logs / K8s audit | CloudTrail / AKV diagnostic logs / GCP Audit Logs | CyberArk PAM audit |
| **On-prem support** | Yes | Yes (STS AssumeRole, Managed Identity, ADC) | Yes |
| **K8s integration** | K8s Secrets + RBAC | IRSA / Workload Identity / Workload Identity Federation | Conjur / Secrets Provider |
| **FIPS support** | Agent 7.76+ (native) | Agent 7.76+ (native) | Partner-implemented |
| **Live rotation** | API/APP key only | API/APP key only | API/APP key only |
| **Partner build burden** | Low | Low | High (custom executable SDLC) |
| **Setup complexity** | Low | Medium | High |
| **Best for** | Greenfield, cost-sensitive, fast starts | Single-cloud-primary environments | Regulated industries with existing PAM mandate |

### Decision Guidelines

**Choose Approach 1 (Platform-Native) if:**

- You want to eliminate hardcoded credentials immediately with no new vendor tooling.
- Cost is a primary concern.
- Your team has strong operational discipline for secret management.
- You have existing CI/CD and configuration management processes.

**Choose Approach 2 (Cloud-Native) if:**

- You are operating primarily within a single cloud provider.
- You want managed rotation, versioning, and cloud-native audit out of the box.
- You prefer cloud-provider-supported services and identity-based access with no long-lived credentials on hosts.

**Choose Approach 3 (CyberArk) if:**

- CyberArk PAM is already deployed in your environment.
- Compliance requires a single unified secrets governance plane across all cloud and on-premises environments.
- You have dedicated security and platform teams who can maintain the custom executable.
- You need enterprise-grade PAM with centralized rotation and full audit across multiple clouds.

---

## Migration Checklist

Use this checklist regardless of which approach you choose:

- [ ] Audit all config files, scripts, and Helm values for hardcoded credentials
- [ ] Inventory every secret by type, platform, and rotation frequency
- [ ] Select and deploy chosen secrets management approach (pilot on one platform first)
- [ ] Confirm Agent version meets the minimum requirement for your chosen approach
- [ ] Install and permission the backend script or configure `secret_backend_type`
- [ ] Configure `datadog.yaml` with `secret_backend_command` or `secret_backend_type`
- [ ] Update integration YAML files to use `ENC[handle]` syntax
- [ ] Verify secret resolution: `sudo datadog-agent secret`
- [ ] Test that `ENC[]` values cover the entire YAML value (not partial strings)
- [ ] Open required firewall/security group rules (see Network Requirements above)
- [ ] Remove all hardcoded credentials from config files and repositories
- [ ] Implement and test rotation procedure including Agent restart
- [ ] Enable audit logging at the backend (CloudTrail / AKV diagnostics / GCP Audit Logs / CyberArk PAM)
- [ ] Document rotation runbook and schedule for each secret type
- [ ] For Windows: verify backend is a valid `.exe` and ACL is correctly set
- [ ] For FIPS environments: confirm Agent 7.76+ with native `secret_backend_type`

---

## Datadog References

- [Datadog Secrets Management Documentation](https://docs.datadoghq.com/agent/configuration/secrets-management/)
- [Datadog Operator — Secret Management](https://docs.datadoghq.com/containers/datadog_operator/secret_management/)
