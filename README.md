# partner-guides

---

# Datadog Customer Checklist

Use a reference when talking to customer

---

##  Checklist

###  AWS Environment
- [ ] AWS account access with proper IAM permissions.
- [ ] Network firewall rules/security groups permitting Datadog Agent traffic.

### Datadog Account
- [ ] Datadog account access.
- [ ] Datadog API keys available and securely stored.

### Infrastructure Monitoring
- [ ] Confirm hosts, containers, and Kubernetes clusters.
- [ ] Confirm operating systems (Linux, Windows).

###  Application Performance Monitoring (APM)
- [ ] Supported application runtimes:
  - [ ] Node.js (version 14+)
  - [ ] Python (FastAPI & Django, version 3.6+)
  - [ ] Java (version 8+)
  - [ ] .NET (.NET Framework 4.5+, .NET Core 2.1+, .NET 5+)

### Log Management
- [ ] Applications producing structured logs.
- [ ] Volume of log data (GB/TB per day).
- [ ] Data retention policies for logs.

###  Real User Monitoring (RUM)
- [ ] Confirm front-end tech stacks (Flutter in this case).
- [ ] Web apps: Ability to inject JavaScript snippet.
- [ ] Mobile apps: Integration of Datadog’s mobile SDK.

###  Security and Access Management
- [ ] Single Sign-On (SSO) and MFA requirements.
- [ ] Define role-based access controls (RBAC).
- [ ] Audit logging requirements.

###  Tagging and Naming Standards
- [ ] AWS tagging strategy for consistent filtering in Datadog.
- [ ] Naming standards for resources and services.

###  Implementation Timeline
- [ ] Key dates for implementation milestones.
- [ ] Availability of team members during setup and testing.
** for later

###  Alerts and Notifications
- [ ] Notification channels (Slack, Teams, PagerDuty).
- [ ] Thresholds and key metrics for alerting.

###  Infrastructure as Code (IaC)
- [ ] IaC tools used (Terraform, CloudFormation).
- [ ] IaC capability for Datadog Agent deployment.

---

# Datadog Implementation Prerequisites (AWS Environment)


---

## General AWS Prerequisites
- **AWS Access:** IAM permissions for Datadog integration (CloudWatch, EC2, RDS, etc.)
- **Security Groups:** Allow Datadog agent traffic ([Datadog Network Requirements](https://docs.datadoghq.com/agent/network/))
- **Tags:** Consistent AWS tags for easy filtering and management.

---

## Datadog Infrastructure & Log Monitoring
- **Agent Installation:** [Datadog Agent](https://docs.datadoghq.com/agent/)
- **Log Collection:** [Log Collection Setup](https://docs.datadoghq.com/logs/log_collection/)

---

##  Datadog APM Prerequisites

### Node.js
- **Version:** Node.js 14.x+
- **Installation:** `npm install dd-trace`
- **Configuration:**
  ```javascript
  const tracer = require('dd-trace').init();
  ```
- [Documentation](https://docs.datadoghq.com/tracing/setup_overview/setup/nodejs/)

### Python (FastAPI & Django)
- **Version:** Python 3.6+
- **Installation:** `pip install ddtrace`
- **Configuration:** `ddtrace-run python app.py`
- [Documentation](https://docs.datadoghq.com/tracing/setup_overview/setup/python/)

### Java (Spring, Apache Tomcat)
- **Version:** Java 8+
- **Configuration:**
  ```bash
  -javaagent:/path/to/dd-java-agent.jar -Ddd.service=<service-name>
  ```
- [Documentation](https://docs.datadoghq.com/tracing/setup_overview/setup/java/)

### .NET
- **Version:** .NET Framework 4.5+, .NET Core 2.1+, .NET 5+
- **Environment Setup:**
  ```
  DD_DOTNET_TRACER_HOME=C:\Program Files\Datadog\.NET Tracer
  ```
- [Documentation](https://docs.datadoghq.com/tracing/setup_overview/setup/dotnet/)

---


---

##  Datadog Real User Monitoring (RUM)

### Flutter & Web (NodeJS)
- Flutter Integration: `flutter pub add datadog_flutter_plugin`
- Browser RUM Setup:
  ```html
  <script src="https://www.datadoghq-browser-agent.com/datadog-rum.js"></script>
  ```
  ```javascript
  DD_RUM.init({
    clientToken: '<CLIENT_TOKEN>',
    applicationId: '<APPLICATION_ID>',
    site: 'datadoghq.com',
    service: 'your-app-service-name'
  });
  ```
- [Flutter Docs](https://docs.datadoghq.com/real_user_monitoring/flutter/)
- [Browser Docs](https://docs.datadoghq.com/real_user_monitoring/browser/)

---

##  Security & Access Management (After doing the main implementation)
- SAML SSO: [Setup](https://docs.datadoghq.com/account_management/saml/)
- Multi-Factor Authentication: [Setup](https://docs.datadoghq.com/account_management/mfa/)
- RBAC: [Setup](https://docs.datadoghq.com/account_management/rbac/)
- Audit Trail: [Setup](https://docs.datadoghq.com/monitors/audit_trail/)

---

- **Note : Make sure you're aligned with the Tagging Strategy:** Consistent tagging for effective monitoring.


