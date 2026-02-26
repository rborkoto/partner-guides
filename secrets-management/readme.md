# Datadog Secrets Management Strategy for Multi-Cloud Environments

## Problem Statement

Infrastructure spans AWS, Azure, GCP, VMware, and on-premises environments. Currently, Datadog API keys and integration credentials such as MySQL passwords are hardcoded in configuration files, scripts, and deployments across platforms. This introduces credential exposure risk, lacks centralized secret management, has no structured key rotation process, and creates potential compliance gaps.

The goal is to move to a secure model where secrets are centrally managed, encrypted, and injected at runtime using identity-based access with no hardcoded credentials.

## Solution Options

This document outlines three approaches to secrets management, each with different trade-offs in terms of complexity, tooling requirements, and operational overhead.

## How Datadog Secrets Management Works

All three approaches use the same Datadog Agent mechanism. The Agent calls a backend executable at startup, passing secret handles via stdin and receiving plaintext values via stdout. Secrets are loaded in memory only and never written to disk.

### Protocol

The Datadog Agent communicates with the backend executable using a JSON protocol:

**Agent sends to executable via stdin:**
```json
{
  "version": "1.0",
  "secrets": ["db.password", "dd.api_key"]
}
```

**Executable must return via stdout:**
```json
{
  "db.password": { "value": "mysecretpassword" },
  "dd.api_key": { "value": "abc123def456" }
}
```

### Integration Configuration

Integration configs reference secrets using ENC[] placeholders:

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[db.password]
```

The Agent resolves `ENC[db.password]` at startup by calling the configured backend. Secrets are never written to disk or exposed in logs.

### Prerequisites

- Datadog Agent 6.12+ for custom executable backends
- Datadog Agent 7.70+ for native backend support (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- For the native `datadog-secret-backend` binary (used in Approach 2), refer to [datadog-secret-backend releases](https://github.com/DataDog/datadog-secret-backend/releases) for version compatibility

---

## 1) Platform-Native Secret Management (No External Tools)

This approach uses no external secrets management tools. It relies on native operating system capabilities, Kubernetes features, and your existing deployment pipeline.

### Goal

- No secrets in code or repositories
- Runtime injection of secrets
- Least privilege access controls
- Repeatable rotation process, even if not fully automated
- No additional vendor tools or licensing costs

### How It Works

#### A) Store Secrets Outside Code

Remove all keys and passwords from scripts, configuration files, Helm values, Terraform variables, and any other version-controlled artifacts. Instead, store secrets in platform-native mechanisms:

**For Kubernetes Workloads:**
- Store secrets in Kubernetes Secrets objects
- Use separate namespaces for different environments
- Reference secrets via environment variables or volume mounts

**For Virtual Machines:**
- Store secrets in root-owned files with strict permissions (mode 0600)
- Use systemd environment files for service configuration
- Place secret files in protected directories like `/etc/datadog-agent/secrets/`

**For SNMP Collectors:**
- Store SNMPv3 credentials and community strings using the same mechanism as the collector host
- For containerized collectors, use Kubernetes Secrets
- For VM-based collectors, use root-owned files with restricted permissions

#### B) Encrypt at Rest (Native)

**Kubernetes:**
- Enable etcd encryption at rest using Kubernetes native encryption providers
- Configure RBAC policies to restrict Secret access to only the Datadog Agent service account
- Use network policies to limit access to etcd

**Virtual Machines:**
- Store secret files on encrypted disks using native full-disk encryption
- For cloud VMs, enable cloud disk encryption (AWS EBS encryption, Azure Disk Encryption, GCP persistent disk encryption)
- Restrict file access to the dd-agent user or root only
- Use filesystem-level encryption if available (LUKS on Linux, BitLocker on Windows)

#### C) Inject at Runtime

**Kubernetes:**
- Mount Kubernetes Secrets as files into the Datadog Agent pod using volume mounts
- Alternatively, inject secrets as environment variables into the Agent container
- Use the same approach for check runner pods and SNMP collector pods
- Ensure secrets are never logged or exposed in pod specifications

**Virtual Machines:**
- Use systemd drop-in environment files that are read at service startup
- Create a root-only file that the Datadog Agent reads on initialization
- Use the Datadog Agent Secrets Management feature to reference secrets via placeholders

**Datadog-Specific Implementation:**
- Configure the Datadog Agent to use its native Secrets Management feature (requires Agent version 7.70 or later)
- Integration configuration files can reference secrets using the ENC[secret_handle] syntax
- The Agent resolves these placeholders at runtime via a local backend command or native backend integration
- This keeps plaintext secrets out of integration YAML files
- Secrets are loaded in memory only and never written to disk
- Reference: https://docs.datadoghq.com/agent/configuration/secrets-management/

#### D) Rotation Process

While not fully automated like a dedicated secrets platform, implement a structured rotation process:

- Maintain a rotation schedule and runbook in your documentation
- Use your CI/CD pipeline or configuration management tool to update secrets
- For Kubernetes: Update the Secret object and restart the Datadog Agent pods
- For VMs: Update the secret file and restart the Datadog Agent service
- Maintain audit evidence from deployment logs showing when rotations occurred
- Document the rotation process for each secret type
- Consider using GitOps tools like ArgoCD or Flux to manage secret updates

### Prerequisites

**Kubernetes:**
- Kubernetes cluster version 1.13 or higher (for encryption at rest)
- RBAC enabled and properly configured
- Access to configure etcd encryption providers (requires cluster admin)
- kubectl access to create and manage Secrets

**Virtual Machines:**
- Root or administrator access to configure file permissions
- Ability to enable disk encryption on VM storage
- Systemd or equivalent service manager (Linux) or Windows Service Manager
- Access to configure Datadog Agent service

**General:**
- Datadog Agent version 7.70 or later (for native secrets management support)
- CI/CD pipeline or configuration management tool (Ansible, Puppet, Chef, etc.)
- Process for secret rotation and documentation
- Access to Datadog Agent configuration files

**Network Connectivity:**

| Endpoint | Purpose | Port/Protocol |
|----------|---------|---------------|
| `*.datadoghq.com` | Agent metrics, APM, logs | HTTPS (443) |
| `intake.logs.datadoghq.com` | Log collection | HTTPS (443) |

Additional considerations:
- For Kubernetes environments: Internal cluster networking for Secret access (no external connectivity required for Secrets)
- For VMs: Local filesystem access only (no external network requirements for secret storage)
- If using custom secret backend command that calls external APIs, ensure connectivity to those endpoints

### High-Level Setup Guidance

**Step 1: Remove Hardcoded Secrets**
- Audit all configuration files, scripts, and deployment manifests
- Identify all hardcoded API keys, passwords, and credentials
- Document the location and purpose of each secret

**Step 2: Create Secret Storage**
- For Kubernetes: Create Secret objects for each environment
- For VMs: Create secret files in protected directories with appropriate permissions
- Ensure encryption at rest is enabled

**Step 3: Configure Datadog Agent Secrets Management**

**For Kubernetes - Store and Mount the Secret:**

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

**Helm chart - reference existing secret instead of hardcoding:**

```yaml
# values.yaml
datadog:
  apiKeyExistingSecret: datadog-secrets
  apiKeyExistingSecretKey: DD_API_KEY

  # Mount additional secrets for integration credentials
  volumes:
    - name: integration-secrets
      secret:
        secretName: datadog-secrets
  volumeMounts:
    - name: integration-secrets
      mountPath: /etc/datadog-agent/secrets
      readOnly: true
```

**For VMs / On-Premises - Store Secrets in a Protected File:**

```bash
# Create secrets directory and file
sudo mkdir -p /etc/datadog-agent/secrets
sudo touch /etc/datadog-agent/secrets/secrets.json
sudo chmod 700 /etc/datadog-agent/secrets
sudo chmod 600 /etc/datadog-agent/secrets/secrets.json
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/secrets.json
```

```json
// /etc/datadog-agent/secrets/secrets.json
{
  "dd.api_key": "your-datadog-api-key",
  "db.password": "your-mysql-password"
}
```

**Backend Script - Read from Local File:**

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
            result[handle] = {"value": store[handle]}
        else:
            result[handle] = {"error": f"handle '{handle}' not found"}
            print(f"Error: secret '{handle}' not found", file=sys.stderr)
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
# Set permissions - Agent will refuse to run world-readable executables
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

**Datadog Agent Configuration:**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[dd.api_key]

secret_backend_command: /etc/datadog-agent/secrets/fetch_secrets.py
secret_backend_timeout: 30
secret_backend_output_max_size: 1048576
```

- Configure the script path in datadog.yaml as secret_backend_command
- Update integration configurations to use ENC[secret_handle] syntax

**Step 4: Update Deployment Process**
- Modify CI/CD pipelines to inject secrets at deployment time
- Update Helm charts or deployment manifests to reference secrets
- Test the deployment process in a non-production environment

**Step 5: Implement Rotation Process**

**For VMs:**
```bash
# 1. Update the secrets file
sudo vi /etc/datadog-agent/secrets/secrets.json

# 2. Restart the Agent to pick up new values
sudo systemctl restart datadog-agent

# 3. Verify resolution
sudo datadog-agent secret
```

**For Kubernetes:**
```bash
# Update the Secret object and trigger a rolling restart
kubectl create secret generic datadog-secrets \
  --from-literal=DD_API_KEY=new-api-key \
  --from-literal=mysql_password=new-password \
  -n datadog --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/datadog-agent -n datadog
```

- Document the rotation schedule for each secret type
- Create automation scripts or playbooks for rotation
- Set up monitoring to alert on secrets approaching expiration

**Step 6: Verify and Audit**
- Verify secrets are not present in logs or configuration dumps
- Test that secrets are properly injected at runtime
- Review access logs to ensure only authorized processes access secrets

### Pros

- No additional vendor tools or licensing costs
- Uses native platform capabilities you already have
- No external dependencies or network calls for secret retrieval
- Simple to understand and maintain
- Works consistently across all platforms using native features
- Low operational overhead once established

### Cons

- Rotation and governance require manual processes and discipline
- Multi-cloud consistency depends on operational discipline across teams
- No centralized audit trail across platforms
- Limited secret versioning and rollback capabilities
- Manual coordination required for secret updates across environments
- Compliance reporting requires aggregating logs from multiple systems

---

## 2) AWS-Native Approach (AWS Secrets Manager + KMS)

This approach uses AWS managed services for secret storage and encryption. AWS Secrets Manager is the secrets management service that stores and manages secrets, while AWS KMS (Key Management Service) provides the encryption layer. This approach is ideal when AWS is the primary or central cloud platform, though it can be extended to other clouds with additional configuration.

### Goal

- Centralized secret management within AWS
- Automated secret rotation
- Versioning and audit trails
- Identity-based access using IAM roles
- Integration with AWS services and workloads

### How It Works

**Secret Storage:**
- Secrets are stored in AWS Secrets Manager (the secrets management service)
- Each secret is encrypted at rest using AWS KMS (Key Management Service) customer master keys
- KMS provides the encryption layer, while Secrets Manager provides the storage and management layer
- Secrets can be structured (JSON) or plaintext
- Secrets Manager maintains version history and rotation metadata

**Access Control:**
- Access is controlled via IAM policies attached to IAM roles
- For EC2 instances, use EC2 instance profiles (automatic credential retrieval)
- For EKS pods, use IAM Roles for Service Accounts (IRSA)
- For Lambda functions, use execution roles
- **For on-premises hosts:** Instance profiles are not available. Must use static AWS credentials via environment variables or configuration file (see Prerequisites section for details)
- IAM policies specify which secrets can be accessed by which roles or users

**Encryption:**
- Secrets Manager automatically encrypts secrets using KMS
- You can use AWS managed keys or customer-managed keys (CMK)
- KMS provides encryption at rest and key rotation
- All API calls to Secrets Manager are encrypted in transit using TLS

**Rotation:**
- Secrets Manager supports automatic rotation using Lambda functions
- Rotation functions can integrate with the source system (database, API, etc.)
- Secrets Manager tracks rotation schedules and triggers rotations automatically
- Previous versions remain available for rollback scenarios

**Runtime Retrieval:**
- Workloads retrieve secrets at runtime using AWS SDK or CLI
- For Datadog Agent on EC2, use instance profile credentials (automatic)
- For EKS pods, use IRSA to assume the IAM role (automatic)
- For on-premises hosts, use static AWS credentials via environment variables or configuration file
- For SNMP collectors in AWS, use the same IAM-based access pattern
- For SNMP collectors on-premises, use static credentials similar to Datadog Agent
- Create a small wrapper script that calls Secrets Manager API and formats output for Datadog Agent (if using custom executable approach)

**Datadog Agent Integration:**
- Create a custom executable script that authenticates using IAM credentials
- Script calls Secrets Manager GetSecretValue API
- Script formats the response according to Datadog Agent secrets management protocol
- Configure the script path in datadog.yaml as secret_backend_command

### Prerequisites

**AWS Account:**
- AWS account with appropriate permissions
- Access to create and manage IAM roles and policies
- Access to create and manage Secrets Manager secrets
- Access to create and manage KMS keys (if using customer-managed keys)

**IAM Configuration:**
- IAM roles for EC2 instances (instance profiles) - for AWS-hosted workloads
- IAM roles for EKS service accounts (IRSA) if using Kubernetes
- IAM policies granting Secrets Manager read access
- IAM policies granting KMS decrypt permissions
- **Important for on-premises hosts:** Instance profiles are not available on non-AWS infrastructure. You must use static AWS credentials (see On-Premises Authentication section below)

**Secrets Manager:**
- Secrets Manager service enabled in target regions
- Secrets created and stored in Secrets Manager
- Rotation Lambda functions configured (if using automatic rotation)

**Network Connectivity:**

All Datadog Agent hosts (EC2 instances, EKS pods, Lambda functions) must have outbound connectivity to the following endpoints:

| Endpoint | Purpose | Port/Protocol |
|----------|---------|---------------|
| `secretsmanager.{region}.amazonaws.com`<br>(e.g., `secretsmanager.us-east-1.amazonaws.com`) | Secrets retrieval via GetSecretValue API | HTTPS (443) |
| `kms.{region}.amazonaws.com`<br>(e.g., `kms.us-east-1.amazonaws.com`) | KMS decrypt operations (automatically called by Secrets Manager) | HTTPS (443) |
| `sts.{region}.amazonaws.com`<br>(e.g., `sts.us-east-1.amazonaws.com`) | IAM role assumption for IRSA or cross-account access | HTTPS (443) |
| `ec2.{region}.amazonaws.com` | EC2 instance metadata service (for instance profile credentials) | HTTPS (443) |
| `169.254.169.254` | EC2 instance metadata service (internal, for instance profile) | HTTP (80) |
| `*.datadoghq.com` | Datadog Agent metrics and logs submission | HTTPS (443) |
| `intake.logs.datadoghq.com` | Log collection | HTTPS (443) |

Additional network considerations:
- For private networking: Configure VPC endpoints for Secrets Manager, KMS, and STS in your VPC
- Security groups and network ACLs must allow outbound HTTPS (443) to AWS service endpoints
- If using VPC endpoints: Ensure route tables and security groups allow traffic to VPC endpoint network interfaces
- For EKS: Ensure pod network policies allow outbound traffic to AWS service endpoints
- Replace `{region}` with your actual AWS region (e.g., us-east-1, eu-west-1)

**Tools:**
- Datadog Agent version 7.70 or later (for native AWS Secrets Manager support)
- AWS CLI or SDK installed on Datadog Agent hosts (if using custom executable approach)
- Python or shell scripting capability for secret retrieval script (if using custom executable)
- IAM instance profile or IRSA configured for authentication (AWS workloads)
- Static AWS credentials for on-premises hosts (see On-Premises Authentication section)

**On-Premises Authentication Considerations:**

For on-premises hosts, instance profiles are not available since they are not running on AWS EC2. You must use one of the following workarounds:

**Option 1: Environment Variables**
Set AWS credentials as environment variables on the Datadog Agent service:
- `AWS_ACCESS_KEY_ID` - AWS access key ID
- `AWS_SECRET_ACCESS_KEY` - AWS secret access key
- `AWS_SESSION_TOKEN` - Optional, for temporary credentials

The Datadog Agent's AWS SDK will automatically pick up these environment variables.

**Option 2: Static Credentials in Configuration**
Include AWS credentials directly in the `secret_backend_config` section of `datadog.yaml`:

```yaml
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: ap-southeast-1
    aws_access_key_id: "..."
    aws_secret_access_key: "..."
```

**Option 3: Environment Variables via Systemd (Linux)**
For systemd services, create a drop-in file at `/etc/systemd/system/datadog-agent.service.d/aws-credentials.conf`:

```ini
[Service]
Environment="AWS_ACCESS_KEY_ID=..."
Environment="AWS_SECRET_ACCESS_KEY=..."
Environment="AWS_REGION=ap-southeast-1"
```

**Option 4: Environment Variables via Environment Variables (Windows)**
Set environment variables in the Datadog Agent service configuration or via system environment variables.

**Security Considerations for Static Credentials:**
- Store static credentials securely (encrypted files, configuration management tools)
- Use IAM users with least privilege access (only Secrets Manager and KMS permissions)
- Rotate static credentials regularly
- Consider using temporary credentials with AWS STS when possible
- Never commit credentials to version control

Reference: https://github.com/DataDog/datadog-secret-backend/blob/main/docs/aws/README.md

### High-Level Setup Guidance

**Step 1: Create KMS Key and Store Secrets**

```bash
# Create a customer-managed KMS key
aws kms create-key \
  --description "Datadog secrets encryption key" \
  --key-usage ENCRYPT_DECRYPT

# Store Datadog API key in Secrets Manager (encrypted with KMS)
aws secretsmanager create-secret \
  --name "datadog/api_key" \
  --secret-string "your-datadog-api-key" \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/your-key-id"

# Store MySQL password as a JSON secret (multiple values in one secret)
aws secretsmanager create-secret \
  --name "datadog/mysql" \
  --secret-string '{"password":"your-mysql-password","username":"datadog"}' \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
```

- Create a KMS customer master key for encrypting secrets
- Configure key policy to allow Secrets Manager service to use the key
- Configure key policy to allow IAM roles to decrypt using the key
- Enable automatic key rotation if desired

**Step 2: Store Secrets in Secrets Manager**
- Create secrets in Secrets Manager for Datadog API key, App key, and integration credentials
- Use structured secrets (JSON) for multiple related values
- Tag secrets appropriately for organization and cost tracking
- Configure automatic rotation if the source system supports it

**Step 3: Create IAM Roles and Policies**

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
- **EC2:** IAM role → instance profile → attached to EC2 instances
- **EKS:** IAM role → annotated on Kubernetes service account (IRSA)
- **On-prem:** IAM user (static credentials)

- For AWS workloads: Create IAM role for Datadog Agent on EC2 instances and attach instance profile
- For EKS: Create IAM role and configure IRSA
- Create IAM user for on-premises hosts (if using static credentials)
- Attach policy allowing secretsmanager:GetSecretValue for specific secrets
- Attach policy allowing kms:Decrypt for the KMS key
- For on-premises: Ensure IAM user has same permissions as IAM role (Secrets Manager read, KMS decrypt)

**Step 4: Install datadog-secret-backend (Recommended)**

Download the binary from the official release page and install it on the Agent host:

```bash
# Example for Linux amd64
curl -L -o /usr/local/bin/datadog-secret-backend \
  https://github.com/DataDog/datadog-secret-backend/releases/latest/download/datadog-secret-backend_linux_amd64

chmod 700 /usr/local/bin/datadog-secret-backend
chown dd-agent:dd-agent /usr/local/bin/datadog-secret-backend
```

**Alternative: Custom Python Script**

If you prefer a custom script instead of the binary:

```python
#!/usr/bin/env python3
# /etc/datadog-agent/secrets/fetch_secrets.py
import json, sys, boto3

REGION = "us-east-1"

def main():
    payload = json.load(sys.stdin)
    client = boto3.client("secretsmanager", region_name=REGION)
    result = {}
    for handle in payload.get("secrets", []):
        try:
            resp = client.get_secret_value(SecretId=handle)
            result[handle] = {"value": resp["SecretString"]}
        except Exception as e:
            result[handle] = {"error": str(e)}
            print(f"Error retrieving {handle}: {e}", file=sys.stderr)
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

**Step 5: Configure Datadog Agent**

**EC2 with Instance Profile (no credentials needed in config):**

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: ENC[datadog/api_key]

secret_backend_command: /usr/local/bin/datadog-secret-backend
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
```

**EKS with IRSA - annotate the service account:**

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
# datadog.yaml (no credentials - IRSA handles auth automatically)
secret_backend_command: /usr/local/bin/datadog-secret-backend
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
```

**On-Premises / Non-AWS Hosts (static IAM credentials required):**

```yaml
# /etc/datadog-agent/datadog.yaml
secret_backend_command: /usr/local/bin/datadog-secret-backend
secret_backend_type: aws.secrets
secret_backend_config:
  aws_session:
    aws_region: us-east-1
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"
    aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Alternatively, inject via systemd to avoid credentials in the YAML file:**

```ini
# /etc/systemd/system/datadog-agent.service.d/aws-credentials.conf
[Service]
Environment="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
Environment="AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Environment="AWS_DEFAULT_REGION=us-east-1"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart datadog-agent
```

**Reference Secrets in Integration Configs:**

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
instances:
  - host: localhost
    username: datadog
    password: ENC[datadog/mysql]   # Secret name in Secrets Manager
```

Note: If the secret is a JSON object with multiple keys, the datadog-secret-backend returns the full JSON string as the value. Parse accordingly, or store individual secrets for each credential.

- Update integration configurations to use ENC[secretId;secretKey] syntax for AWS Secrets Manager
- Test secret retrieval and Agent startup

**Step 6: Verify and Test**

```bash
# Check that secrets are being resolved correctly
sudo datadog-agent secret

# Check Agent status
sudo datadog-agent status
```

- **For AWS workloads:**
  - Attach IAM instance profile to EC2 instances running Datadog Agent
  - For EKS, annotate service account with IAM role ARN
- **For on-premises hosts:**
  - Ensure AWS credentials are configured (via environment variables or config file)
  - Verify credentials have proper IAM permissions
  - Test connectivity to AWS Secrets Manager endpoints
- Deploy Datadog Agent and verify secrets are retrieved correctly
- Monitor CloudTrail logs for Secrets Manager API calls
- Verify secrets are resolved correctly using `datadog-agent status` command

**Step 7: Configure Rotation (Optional)**
- Create Lambda function for secret rotation if applicable
- Configure Secrets Manager to use the rotation function
- Test rotation process in non-production environment
- Monitor rotation success and failures


---

## 3) CyberArk Approach (Centralized Hybrid Secrets Management)

This approach uses CyberArk as a centralized secrets management platform across all cloud providers and on-premises environments. It provides a single control plane for secret governance, rotation, and audit across the entire hybrid infrastructure.

### Goal

- Centralized secret management across AWS, Azure, GCP, and on-premises
- Unified governance and compliance reporting
- Automated secret rotation with centralized policies
- Identity-based access using cloud-native identities
- Comprehensive audit trail and access controls

### How It Works

**Secret Storage:**
- Secrets are stored in CyberArk Vault (on-premises or cloud)
- CyberArk manages encryption keys and access policies
- Secrets can be organized by platform, application, or environment
- CyberArk maintains version history and rotation schedules

**Access Control:**
- Access is controlled via CyberArk policies and safes
- Authentication uses identity providers:
  - AWS: IAM roles via CyberArk AWS integration
  - Azure: Managed Identities via CyberArk Azure integration
  - GCP: Service Accounts via CyberArk GCP integration
  - On-premises: LDAP, Active Directory, or certificates
- CyberArk validates identity and grants access based on policies

**Encryption:**
- CyberArk encrypts secrets at rest using its internal key management
- All communications with CyberArk are encrypted in transit using TLS
- CyberArk can integrate with cloud KMS for additional encryption layers
- Key rotation is managed by CyberArk automatically

**Rotation:**
- CyberArk provides automated rotation capabilities
- Rotation policies can be defined centrally and applied across platforms
- Rotation can be triggered on schedule or on-demand
- Integration with target systems (databases, APIs) for seamless rotation
- Previous versions remain available for audit and rollback

**Runtime Injection:**
- For Virtual Machines: Use CyberArk agent or provider installed on the host
- For Kubernetes: Use Conjur (CyberArk's Kubernetes integration) or CSI driver
- For containerized workloads: Use sidecar pattern with CyberArk provider
- For SNMP collectors: Use the same injection mechanism as the collector host

**Datadog Agent Integration:**
- Create a custom executable that authenticates to CyberArk using platform identity
- Script calls CyberArk API to retrieve secrets
- Script formats response according to Datadog Agent secrets management protocol
- Configure the script path in datadog.yaml as secret_backend_command
- Alternatively, use CyberArk Conjur for Kubernetes environments with native integration

**Multi-Cloud Architecture:**
- CyberArk central vault can be deployed on-premises or in a central cloud region
- Regional replicas or caching can improve performance
- CyberArk agents or providers installed on each platform handle local authentication
- All access attempts and secret retrievals are logged centrally

### Prerequisites

**CyberArk Infrastructure:**
- CyberArk Vault deployed and configured (on-premises or cloud)
- CyberArk license and support agreement
- CyberArk administrators trained and available

**Identity Configuration:**
- AWS: IAM roles configured and CyberArk AWS integration set up
- Azure: Managed Identities configured and CyberArk Azure integration set up
- GCP: Service Accounts configured and CyberArk GCP integration set up
- On-premises: LDAP/AD integration or certificate-based authentication configured

**Platform-Specific Components:**
- For VMs: CyberArk agent or provider installed on Datadog Agent hosts
- For Kubernetes: CyberArk Conjur or CSI driver installed in clusters
- For containers: CyberArk sidecar or init container capability
- Network policies allowing communication with CyberArk

**Access and Permissions:**
- CyberArk safes created for Datadog secrets
- CyberArk policies configured for Datadog Agent access
- Platform identities (IAM roles, Managed Identities, Service Accounts) registered in CyberArk
- CyberArk administrators with appropriate permissions

**Tools and Scripts:**
- Datadog Agent version 7.70 or later
- CyberArk API access or CLI tools
- Scripting capability (Python, PowerShell, or shell) for secret retrieval script
- Custom executable that implements Datadog Agent secret backend command protocol

**Network Connectivity:**

All Datadog Agent hosts must have outbound connectivity to the following endpoints:

| Endpoint | Purpose | Port/Protocol |
|----------|---------|---------------|
| CyberArk Vault endpoint<br>(hostname or IP address) | Secret retrieval via CyberArk API | HTTPS (443) or custom port if configured |
| CyberArk Conjur endpoint<br>(if using Kubernetes Conjur integration) | Secret retrieval for Kubernetes workloads | HTTPS (443) |
| Platform identity endpoints (for authentication): | | |
| `sts.{region}.amazonaws.com`<br>(AWS only) | IAM role assumption for AWS authentication | HTTPS (443) |
| `169.254.169.254`<br>(AWS - internal only) | EC2 instance metadata service | HTTP (80) |
| `169.254.169.254`<br>(Azure - internal only) | Azure instance metadata service | HTTP (80) |
| `169.254.169.254`<br>(GCP - internal only) | GCP metadata service | HTTP (80) |
| `*.datadoghq.com` | Datadog Agent metrics and logs submission | HTTPS (443) |
| `intake.logs.datadoghq.com` | Log collection | HTTPS (443) |

Additional network considerations:
- For on-premises deployments: Ensure firewall rules allow outbound HTTPS to CyberArk Vault
- For cloud deployments: Configure security groups and network ACLs to allow outbound HTTPS to CyberArk Vault
- For Kubernetes: Ensure pod network policies allow outbound traffic to CyberArk endpoints
- If CyberArk Vault is behind a VPN or private network: Configure VPN connectivity or private network peering
- For high availability: Ensure connectivity to all CyberArk Vault replicas if using multi-region setup
- Replace `{region}` with your actual AWS region if applicable

### High-Level Setup Guidance

**Step 1: Deploy and Configure CyberArk Vault**
- Deploy CyberArk Vault in central location (on-premises or cloud)
- Configure high availability and backup procedures
- Set up network connectivity from all target platforms
- Configure CyberArk administrators and access controls

**Step 2: Configure Platform Integrations**
- Set up CyberArk AWS integration and configure IAM role authentication
- Set up CyberArk Azure integration and configure Managed Identity authentication
- Set up CyberArk GCP integration and configure Service Account authentication
- Configure on-premises authentication (LDAP, AD, or certificates)

**Step 3: Create Safes and Policies**
- Create CyberArk safes for Datadog secrets (one per environment if needed)
- Configure safe policies with appropriate access controls
- Add platform identities (IAM roles, Managed Identities, Service Accounts) to safes
- Configure rotation policies for secrets that support rotation

**Step 4: Store Secrets in CyberArk Vault**

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

Grant your platform identities (IAM role ARN, Managed Identity, AD account) access to the appropriate Safe via CyberArk Access Control policies.

- Store Datadog API key and App key in CyberArk
- Store integration credentials (MySQL, PostgreSQL, etc.) in CyberArk
- Organize secrets using folders or naming conventions
- Tag secrets for organization and reporting

**Step 5: Install Platform Components**
- For VMs: Install CyberArk agent or provider on Datadog Agent hosts
- For Kubernetes: Install CyberArk Conjur or CSI driver in clusters
- Configure components to authenticate using platform identities
- Test connectivity and authentication

**Step 6: Create Secret Retrieval Script**

**Backend Script Using CyberArk AIM (Application Identity Manager):**

For VM and on-premises hosts using CyberArk's Central Credential Provider (CCP):

```python
#!/usr/bin/env python3
# /etc/datadog-agent/secrets/fetch_secrets.py
import json, sys, requests

# CyberArk Central Credential Provider endpoint
CYBERARK_URL = "https://cyberark.internal.example.com"
APP_ID = "DatadogAgent"
# Certificate-based auth (recommended) - adjust path as needed
CERT = ("/etc/datadog-agent/secrets/client.crt", "/etc/datadog-agent/secrets/client.key")
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
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()["Content"]

def main():
    payload = json.load(sys.stdin)
    result = {}
    for handle in payload.get("secrets", []):
        try:
            result[handle] = {"value": get_secret(handle)}
        except Exception as e:
            result[handle] = {"error": str(e)}
            print(f"Error retrieving '{handle}': {e}", file=sys.stderr)
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 700 /etc/datadog-agent/secrets/fetch_secrets.py
sudo chown dd-agent:dd-agent /etc/datadog-agent/secrets/fetch_secrets.py
```

- Write custom executable script that implements Datadog Agent secret backend command protocol
- Script should authenticate to CyberArk using platform identity (IAM role, Managed Identity, Service Account, or certificates)
- Script should call CyberArk API to retrieve secrets based on secret handles from Datadog Agent
- Script must parse JSON input from Datadog Agent and return JSON output in the required format
- Handle authentication, errors, and logging appropriately (errors to stderr, output to stdout)

**Step 7: Configure Datadog Agent**

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

**Kubernetes with Conjur (CyberArk's K8s Integration):**

For Kubernetes workloads, use the CyberArk Secrets Provider for Kubernetes to sync Conjur secrets into Kubernetes Secrets at pod startup:

```yaml
# conjur-secrets-provider.yaml - init container approach
apiVersion: apps/v1
kind: Deployment
metadata:
  name: datadog-agent
  namespace: datadog
spec:
  template:
    spec:
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
                name: datadog-secrets   # Populated by the init container
```

```yaml
# conjur-policy.yaml - grant EKS service account access to Conjur secrets
- !policy
  id: datadog
  body:
    - !host datadog-agent
    - !permit
      role: !host datadog-agent
      privileges: [read, execute]
      resources:
        - !variable datadog/api_key
        - !variable datadog/mysql_password
```

- Install secret retrieval script with appropriate permissions (700 on Linux, restricted on Windows)
- Configure datadog.yaml with secret_backend_command pointing to script
- Set secret_backend_timeout and secret_backend_output_max_size as needed
- Update integration configurations to use ENC[secret_handle] syntax where secret_handle maps to CyberArk secret identifier
- Test secret retrieval and Agent startup on each platform

**Step 8: Configure Rotation**
- Set up rotation policies in CyberArk for applicable secrets
- Configure rotation schedules and triggers
- Test rotation process in non-production environment
- Monitor rotation success and handle failures

**Step 9: Deploy Across Platforms**
- Deploy Datadog Agent with CyberArk integration on AWS
- Deploy Datadog Agent with CyberArk integration on Azure
- Deploy Datadog Agent with CyberArk integration on GCP
- Deploy Datadog Agent with CyberArk integration on on-premises
- Verify secrets are retrieved correctly on all platforms

**Step 10: Verify and Monitor**

```bash
# Test the backend script directly before configuring the Agent
echo '{"version": "1.0", "secrets": ["DatadogProd/datadog-api-key"]}' \
  | sudo -u dd-agent /etc/datadog-agent/secrets/fetch_secrets.py

# After Agent configuration
sudo datadog-agent secret
sudo datadog-agent status
```

- Review CyberArk audit logs for secret access
- Monitor for failed authentication attempts
- Set up alerts for rotation failures
- Generate compliance reports from CyberArk


---

## Comparison & Decision Guide

| Feature | Approach 1: Platform-Native | Approach 2: AWS Secrets Manager | Approach 3: CyberArk |
|---------|----------------------------|-------------------------------|---------------------|
| **External tooling** | None | AWS account | CyberArk license + deployment |
| **Multi-cloud support** | Yes (per-platform storage) | Limited (on-prem needs static creds) | Yes (native) |
| **Automatic rotation** | Manual / CI-CD | Yes (via Lambda) | Yes (centralized) |
| **Audit trail** | Deployment logs | CloudTrail | CyberArk audit logs |
| **On-prem support** | Yes | Yes (with static IAM creds) | Yes |
| **K8s integration** | K8s Secrets + RBAC | IRSA + native backend | Conjur / CSI driver |
| **Setup complexity** | Low | Medium | High |
| **Best for** | Getting started quickly, cost-sensitive | AWS-primary environments | Existing CyberArk users, strict compliance |

### Decision Guidelines

**Choose Approach 1 (Platform-Native) if:**
- You want to eliminate hardcoded credentials immediately with no new vendor tooling
- You can enforce rotation via process/CI-CD
- Cost is a primary concern
- Your team has strong operational discipline for secret management
- You have existing CI/CD and configuration management processes

**Choose Approach 2 (AWS Secrets Manager) if:**
- AWS is your primary platform
- You want managed rotation, versioning, and CloudTrail audit out of the box
- You prefer AWS-native services and integrations
- You have AWS expertise in your team
- Note that non-AWS hosts require static IAM credentials

**Choose Approach 3 (CyberArk) if:**
- CyberArk is already deployed in your environment
- Compliance requires a single unified secrets governance plane across all cloud and on-premises environments
- You need centralized governance across multiple clouds
- You have dedicated security and platform teams
- You need enterprise-grade secret rotation and management

## Migration Checklist

Use this checklist to guide your migration regardless of which approach you choose:

- [ ] Audit all config files, scripts, and Helm values for hardcoded credentials
- [ ] Inventory every secret by type, platform, and rotation frequency
- [ ] Select and deploy chosen secrets management approach (pilot on one platform first)
- [ ] Install and permission the backend script or datadog-secret-backend binary
- [ ] Configure datadog.yaml with secret_backend_command
- [ ] Update integration YAML files to use ENC[handle] syntax
- [ ] Verify secret resolution: `sudo datadog-agent secret`
- [ ] Open required firewall/security group rules (see Network Requirements sections above)
- [ ] Remove all hardcoded credentials from config files and repositories
- [ ] Implement and test rotation procedure
- [ ] Enable audit logging (CloudTrail / CyberArk audit / K8s audit log)
- [ ] Document rotation runbook and schedule for each secret type

## References

- [Datadog Secrets Management Documentation](https://docs.datadoghq.com/agent/configuration/secrets-management/)
- [datadog-secret-backend (AWS Secrets Manager / SSM native backend)](https://github.com/DataDog/datadog-secret-backend)
- [CyberArk Secrets Provider for Kubernetes](https://github.com/cyberark/secrets-provider-for-k8s)
- [AWS Secrets Manager VPC Endpoints](https://docs.aws.amazon.com/secretsmanager/latest/userguide/vpc-endpoints-overview.html)
