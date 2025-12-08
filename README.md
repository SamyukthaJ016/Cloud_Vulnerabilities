# Multi-Cloud Security Scanner

A comprehensive Cloud Security Posture Management (CSPM) tool that scans AWS, GCP, and OpenAI for security vulnerabilities and generates AI-powered remediation recommendations.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## 🎯 Overview

This security scanner automates the discovery of cloud resources, identifies misconfigurations and vulnerabilities, maps findings to compliance standards (CIS, NIST, OWASP), and provides AI-generated remediation plans.

### Key Features

- ✅ **Multi-Cloud Support**: Scan AWS, GCP, and OpenAI in a single operation
- ✅ **Real Vulnerability Detection**: Identifies actual security issues, not just config checks
- ✅ **AI-Powered Recommendations**: GPT-4 analyzes findings and creates actionable remediation plans
- ✅ **Compliance Mapping**: Maps findings to CIS, NIST, OWASP standards
- ✅ **Risk Prioritization**: Intelligent scoring based on severity and exploitability
- ✅ **Historical Tracking**: PostgreSQL database tracks scans over time
- ✅ **RESTful API**: FastAPI-based API for integration with other tools
- ✅ **Interactive CLI**: User-friendly command-line interface with guided setup

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI REST API                     │
│              (main.py - Orchestration Layer)            │
└────────────────────┬───────────────────────────────────┘
                     │
        ┌────────────┴─────────────┬──────────────┐
        ▼                          ▼              ▼
   ┌─────────┐              ┌──────────┐    ┌──────────┐
   │   AWS   │              │   GCP    │    │  OpenAI  │
   │ Plugin  │              │  Plugin  │    │  Plugin  │
   └─────────┘              └──────────┘    └──────────┘
        │                          │              │
        └──────────┬───────────────┴──────────────┘
                   ▼
            ┌─────────────┐
            │  MCP Base   │  ← Plugin Interface
            │  (3 Tools)  │
            └─────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
   ┌──────────┐         ┌──────────────┐
   │PostgreSQL│         │ AI Engine    │
   │ Database │         │(GPT Analysis)│
   └──────────┘         └──────────────┘
```

### Component Breakdown

#### **Core Components**

1. **MCP Base Interface** (`mcp_base.py`)
   - Defines the plugin contract all cloud providers must implement
   - Three required methods: `discover_resources()`, `check_config()`, `assess_vulnerabilities()`
   - Standardized data structures: `CloudResource`, `SecurityFinding`, `ScanResult`

2. **Cloud Plugins**
   - **AWS Plugin** (`mcp_aws_plugin.py`): Scans S3, IAM, EC2 Security Groups, CloudTrail, KMS
   - **GCP Plugin** (`mcp_gcp_plugin.py`): Scans GCS buckets, IAM, Firewall Rules, Cloud SQL
   - **OpenAI Plugin** (`mcp_openai_plugin.py`): Scans API keys, model access, usage patterns

3. **AI Recommendation Engine** (`ai_recommender.py`)
   - Analyzes scan results using GPT-4
   - Generates security posture assessments
   - Creates 7-day remediation plans
   - Prioritizes risks by exploitability

4. **Database Layer** (`database.py`)
   - PostgreSQL persistence for all scan data
   - Tracks resources, findings, and scan history
   - Enables trend analysis and compliance reporting

5. **API Layer** (`main.py`)
   - FastAPI REST endpoints
   - Natural language scan orchestration (AI determines what to scan)
   - Multi-cloud scan coordination
   - Dashboard and reporting endpoints

6. **Interactive Scanner** (`interactive_scanner.py`)
   - CLI interface with guided credential setup
   - Real-time credential validation
   - Formatted result display
   - AI recommendations integrated

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- PostgreSQL 12 or higher
- Cloud provider accounts (AWS, GCP, and/or OpenAI)
- API keys/credentials for each provider you want to scan

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cloud-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up database
createdb mcp_scanner
psql mcp_scanner < schema.sql

# Create .env file
cp .env.example .env
# Edit .env with your credentials
```

### Configuration

Create a `.env` file with your credentials:

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost/mcp_scanner

# AWS Credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1

# GCP Credentials
GCP_SERVICE_ACCOUNT_JSON=./gcp-service-account.json
GCP_PROJECT_ID=your-project-id

# OpenAI Credentials
OPENAI_API_KEY=sk-your-api-key
OPENAI_ORG_ID=org-your-org-id
```

### Usage

#### Interactive Mode (Recommended for First Use)

```bash
python interactive_scanner.py
```

Follow the prompts to:
1. Select cloud providers to scan
2. Enter credentials (or use from .env)
3. Validate credentials automatically
4. Execute security scans
5. View formatted results and AI recommendations

#### API Mode

Start the FastAPI server:

```bash
python main.py
```

Access the API:

```bash
# Natural language scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"message": "Scan my AWS and GCP accounts for security issues"}'

# Direct multi-cloud scan
curl -X POST http://localhost:8000/scan/multi-cloud \
  -H "Content-Type: application/json" \
  -d '{
    "providers": ["aws", "gcp"],
    "account_ids": {"aws": "123456789012", "gcp": "my-project"}
  }'

# View dashboard
curl http://localhost:8000/posture/dashboard

# Get specific scan report
curl http://localhost:8000/report/42
```

#### View Database Results

```bash
python view_database.py
```

Or use psql directly:

```bash
psql $DATABASE_URL -c "SELECT * FROM scans ORDER BY id DESC LIMIT 5;"
```

## 📊 What Gets Scanned

### AWS Resources

| Resource Type | Security Checks |
|---------------|-----------------|
| **S3 Buckets** | Public access, encryption, versioning, logging, policies |
| **IAM Users** | MFA status, access key age, admin privileges, password policies |
| **Security Groups** | Open ports (SSH/RDP/databases), source IP restrictions |
| **CloudTrail** | Logging status, log validation, multi-region trails |
| **KMS Keys** | Key rotation, key policies, encryption usage |

### GCP Resources

| Resource Type | Security Checks |
|---------------|-----------------|
| **GCS Buckets** | Public access (allUsers/allAuthenticatedUsers), CMEK encryption, versioning, logging |
| **IAM Bindings** | Service account privileges, overly permissive roles |
| **Firewall Rules** | SSH/RDP exposed to internet, source IP restrictions |
| **Cloud SQL** | Public IP addresses, SSL enforcement, backup configuration |
| **Compute Instances** | External IPs, default service accounts, OS login |

### OpenAI Resources

| Resource Type | Security Checks |
|---------------|-----------------|
| **API Keys** | Rotation schedule, exposure risks, permission scope |
| **Model Access** | GPT-4 governance, content filtering, prompt injection protection |
| **Usage Patterns** | Rate limiting, usage alerts, request logging |

## 🔒 Security Findings Examples

### Critical Findings

- 🔴 **Public S3/GCS Buckets**: Data exposed to the internet
- 🔴 **IAM Users Without MFA**: Account takeover risk
- 🔴 **SSH/RDP Open to World**: Brute force attack surface
- 🔴 **CloudTrail Logging Disabled**: No audit trail

### High Findings

- 🟠 **Missing Encryption**: Data at rest not protected
- 🟠 **Old Access Keys**: Credentials in circulation too long
- 🟠 **Database Ports Exposed**: Direct database access risk
- 🟠 **Admin Access to Service Accounts**: Excessive privileges

### Medium/Low Findings

- 🟡 **Versioning Disabled**: Data loss risk
- 🔵 **Access Logging Disabled**: No audit capability

## 📈 Compliance Standards

Findings are mapped to industry frameworks:

- **CIS Benchmarks**: AWS Foundations, GCP Foundations
- **NIST 800-53**: Security and Privacy Controls
- **OWASP**: API Security Top 10, LLM Top 10

Example compliance output:
```json
{
  "finding": "Public S3 Bucket",
  "compliance": [
    "CIS-2.1.5",
    "NIST-800-53-AC-3",
    "OWASP-API-8"
  ]
}
```

## 🤖 AI-Powered Features

### Security Analysis

GPT-4 analyzes scan results to provide:
- Overall security posture rating (Critical/Poor/Fair/Good/Excellent)
- Top 3 most critical risks with business impact
- Exploitable attack vectors
- Compliance concerns
- Immediate 24-hour action items

### 7-Day Remediation Plan

AI generates a week-by-week plan prioritized by:
1. Exploitability (public resources first)
2. Data sensitivity (encryption, IAM issues)
3. Compliance requirements
4. Ease of remediation

Example output:
```json
{
  "day_1": {
    "focus": "Emergency critical issues",
    "tasks": [
      "Block public access on prod-data-bucket",
      "Enable MFA for admin users"
    ],
    "priority": "CRITICAL"
  },
  "day_2": { ... }
}
```

### Risk Prioritization

Intelligent scoring algorithm:
```
risk_score = base_severity_score
           + (3 if publicly_exposed)
           + (2 if iam_or_keys_related)
```

Findings are ranked by exploitability, not just severity.

## 📚 Database Schema

### Tables

**scans**
- Tracks each security scan session
- Stores: scan_id, account_id, cloud provider, status, timestamps

**resources**
- Catalogs discovered cloud assets
- Stores: resource_type, name, configuration (JSONB), public exposure flag
- Linked to parent scan via foreign key

**findings**
- Records security vulnerabilities
- Stores: severity, description, affected resource, compliance standards
- Enables reporting and trend analysis

### Example Queries

```sql
-- View latest scan summary
SELECT 
    s.cloud,
    COUNT(DISTINCT r.id) as resources,
    COUNT(f.id) as findings,
    COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) as critical
FROM scans s
LEFT JOIN resources r ON s.id = r.scan_id
LEFT JOIN findings f ON s.id = f.scan_id
WHERE s.id = (SELECT MAX(id) FROM scans)
GROUP BY s.cloud;

-- View critical findings
SELECT 
    f.severity,
    r.cloud,
    r.name,
    f.description
FROM findings f
JOIN resources r ON f.resource_id = r.id
WHERE f.severity = 'CRITICAL'
ORDER BY f.id DESC;
```

## 🔧 Troubleshooting

### AWS Permission Errors

**Error**: `AccessDenied when calling ListUsers`

**Solution**: Attach `SecurityAudit` managed policy to your IAM user:
```bash
aws iam attach-user-policy \
  --user-name your-scanner-user \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

### GCP API Errors

**Error**: `API has not been used in project before`

**Solution**: Enable required APIs:
```bash
gcloud services enable storage-component.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable sqladmin.googleapis.com
```

### Database Connection Errors

**Error**: `could not connect to server`

**Solution**: Ensure PostgreSQL is running:
```bash
# macOS
brew services start postgresql@14

# Linux
sudo systemctl start postgresql

# Check connection
psql $DATABASE_URL -c "SELECT 1"
```

### JSON Serialization Errors

**Error**: `Object of type datetime is not JSON serializable`

**Solution**: Ensure `database.py` has the `json_serial` function and uses it in `store_resource()`:
```python
config_json = json.dumps(config, default=json_serial)
```

License

MIT License - See LICENSE file for details

Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- AI analysis powered by [OpenAI GPT-4](https://openai.com/)
- Cloud SDKs: [boto3](https://boto3.amazonaws.com/), [google-cloud-python](https://github.com/googleapis/google-cloud-python)
- Inspired by commercial CSPM tools like Wiz, Prisma Cloud, and Lacework


⚠️ Disclaimer

This tool is for security auditing and compliance monitoring. Always ensure you have proper authorization before scanning cloud resources. The scanner requires read-only permissions and does not modify any resources.

---

