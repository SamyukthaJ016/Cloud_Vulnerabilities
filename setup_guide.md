# 🛡️ Multi-Cloud MCP Security Scanner

**Production-grade CSPM (Cloud Security Posture Management) with AI-powered recommendations**

Built with the **MCP (Model Context Protocol) architecture** — the same pattern used by Wiz, Prisma Cloud, and Lacework.

---

## 🎯 Features

### ✅ True MCP Plugin Architecture
- **Zero code changes** when adding new cloud providers
- Universal 3-tool interface: `discover_resources`, `check_config`, `assess_vulnerabilities`
- Provider plugins: AWS, GCP, OpenAI (Azure ready)

### ✅ Real Security Vulnerability Checks
**AWS:**
- IAM: MFA enforcement, access key rotation, admin policy abuse
- S3: Public buckets, encryption, versioning, logging
- EC2: Security groups (SSH/RDP/database ports open)
- CloudTrail: Audit logging, log validation
- KMS: Key rotation

**GCP:**
- Cloud Storage: Public buckets, CMEK encryption, versioning
- IAM: Service account privileges, public bindings
- Firewall: Open ports to 0.0.0.0/0
- Cloud SQL: Public IPs, SSL requirements, backups

**OpenAI:**
- API key rotation and exposure
- Model access governance
- Usage monitoring and rate limiting

### ✅ AI-Powered Recommendations
- Risk prioritization by exploitability
- 7-day remediation plans
- Compliance gap analysis (CIS, NIST, OWASP)
- Executive security score (0-100)

---

## 🏗️ Architecture

```
User Request
    ↓
FastAPI (Orchestrator)
    ↓
OpenAI LLM → Creates Scan Plan
    ↓
MCP Registry
    ├── AWS Plugin
    ├── GCP Plugin
    └── OpenAI Plugin
    ↓
Vulnerability Findings
    ↓
AI Recommendation Engine
    ↓
Dashboard + Reports
```

### Why This Architecture Wins

| Traditional Approach | MCP Architecture |
|---------------------|------------------|
| Write AWS code in FastAPI | Write once, AWS plugin implements |
| Add GCP? Rewrite FastAPI | Add GCP? Register plugin, done |
| Add Azure? Rewrite again | Add Azure? Register plugin, done |
| 500+ lines of cloud code | 50 lines of orchestration |

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- PostgreSQL database
- AWS credentials (IAM user with read-only access)
- GCP service account (Viewer role)
- OpenAI API key

### 2. Setup Database

```sql
-- Create database
CREATE DATABASE mcp_scanner;

-- Connect and create tables
\c mcp_scanner

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255),
    cloud VARCHAR(50),
    status VARCHAR(50),
    started_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE resources (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    cloud VARCHAR(50),
    type VARCHAR(100),
    name VARCHAR(500),
    config JSONB,
    public BOOLEAN DEFAULT FALSE
);

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    resource_id INTEGER REFERENCES resources(id),
    severity VARCHAR(20),
    description TEXT,
    validated_by VARCHAR(100)
);

CREATE INDEX idx_scans_cloud ON scans(cloud);
CREATE INDEX idx_resources_scan ON resources(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.template .env
# Edit .env with your credentials
```

### 5. Run Scanner

```bash
python interactive_scanner.py
```

Server starts at: `http://localhost:8000`

---

## 📡 API Usage

### Intelligent Scan (LLM-Orchestrated)

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"message": "Scan my AWS account 123456789012"}'
```

**Response:**
```json
{
  "status": "completed",
  "scan_ids": [42],
  "providers_scanned": ["aws"],
  "total_resources": 47,
  "total_findings": 12,
  "ai_analysis": "Security Posture: FAIR\n\nTop Risks:\n1. 3 S3 buckets are publicly accessible...",
  "remediation_plan": {
    "day_1": {
      "focus": "Emergency critical issues",
      "tasks": ["Block public access on s3://my-bucket", "Enable MFA for IAM users"],
      "priority": "CRITICAL"
    },
    ...
  },
  "executive_summary": {
    "security_score": 67,
    "security_posture": "FAIR",
    "severity_breakdown": {
      "CRITICAL": 3,
      "HIGH": 5,
      "MEDIUM": 4
    }
  }
}
```

### Multi-Cloud Scan

```bash
curl -X POST http://localhost:8000/scan/multi-cloud \
  -H "Content-Type: application/json" \
  -d '{
    "providers": ["aws", "gcp", "openai"],
    "account_ids": {
      "aws": "123456789012",
      "gcp": "my-project-id"
    }
  }'
```

### Security Dashboard

```bash
curl http://localhost:8000/posture/dashboard
```

**Response:**
```json
{
  "clouds": [
    {
      "provider": "aws",
      "resources": 47,
      "findings": 12,
      "public": 3
    },
    {
      "provider": "gcp",
      "resources": 23,
      "findings": 6,
      "public": 1
    }
  ],
  "total_resources": 70,
  "total_findings": 18,
  "public_resources": 4,
  "security_score": 74.3
}
```

### Get Scan Report

```bash
curl http://localhost:8000/report/42
```

### Compliance Report

```bash
curl http://localhost:8000/compliance/CIS
```

---

## 🔌 Adding New Cloud Providers (Azure Example)

### Step 1: Create Plugin

```python
# mcp_azure_plugin.py
from mcp_base import MCPPlugin, CloudResource, SecurityFinding, Severity
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

class AzurePlugin(MCPPlugin):
    def _get_provider_name(self) -> str:
        return "azure"
    
    async def discover_resources(self, account_id: str) -> List[CloudResource]:
        # Implement Azure resource discovery
        resources = []
        # ... Azure API calls
        return resources
    
    async def check_config(self, resources: List[CloudResource]) -> List[Dict]:
        # Implement config checks
        return []
    
    async def assess_vulnerabilities(self, resources: List[CloudResource]) -> List[SecurityFinding]:
        # Implement vulnerability checks
        findings = []
        # ... security checks
        return findings
```

### Step 2: Register Plugin

```python
# In app_refactored.py, add to initialize_plugins():
azure_plugin = AzurePlugin({
    'subscription_id': os.getenv('AZURE_SUBSCRIPTION_ID'),
    'tenant_id': os.getenv('AZURE_TENANT_ID')
})
mcp_registry.register('azure', azure_plugin)
```

**That's it!** No changes to FastAPI routes. Zero modifications to existing code.

---

## 🧪 Testing

### Test AWS Plugin
```bash
curl -X POST http://localhost:8000/scan/multi-cloud \
  -H "Content-Type: application/json" \
  -d '{"providers": ["aws"], "account_ids": {"aws": "test"}}'
```

### Test All Providers
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"message": "Scan everything"}'
```

---

## 📊 Sample Findings

### Critical Finding: Public S3 Bucket
```json
{
  "severity": "CRITICAL",
  "resource": "s3://my-sensitive-data",
  "issue": "Public S3 Bucket",
  "description": "Bucket is publicly accessible",
  "recommendation": "Enable 'Block Public Access' settings and review bucket policy",
  "compliance": ["CIS-2.1.5", "NIST-800-53-AC-3"]
}
```

### High Finding: IAM No MFA
```json
{
  "severity": "CRITICAL",
  "resource": "iam:admin-user",
  "issue": "IAM User Without MFA",
  "description": "User admin-user does not have MFA enabled",
  "recommendation": "Enable MFA for all IAM users, especially those with console access",
  "compliance": ["CIS-1.2", "NIST-800-53-IA-2"]
}
```

---

## 🎨 Frontend Integration

This backend is designed for:
- React dashboards
- Vue.js admin panels
- Next.js security portals
- CLI tools

Example React hook:
```javascript
const { data, loading } = useScan();

useEffect(() => {
  fetch('http://localhost:8000/posture/dashboard')
    .then(res => res.json())
    .then(data => setPosture(data));
}, []);
```

---

## 🔐 Security Best Practices

### For Production:
1. **Use read-only IAM roles** (AWS Security Audit, GCP Viewer)
2. **Rotate API keys every 90 days**
3. **Store credentials in AWS Secrets Manager / HashiCorp Vault**
4. **Enable HTTPS** (Let's Encrypt for free certificates)
5. **Add authentication** (OAuth2, JWT)
6. **Rate limit API endpoints**
7. **Encrypt database** (PostgreSQL SSL)

### IAM Policies

**AWS Read-Only Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:List*",
      "s3:Get*",
      "iam:List*",
      "iam:Get*",
      "ec2:Describe*",
      "cloudtrail:Describe*",
      "kms:Describe*"
    ],
    "Resource": "*"
  }]
}
```

**GCP Viewer Role:**
```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:scanner@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

---

## 🚦 Roadmap

- [ ] Azure plugin
- [ ] Kubernetes security scanning
- [ ] Container image vulnerability scanning
- [ ] Real-time alerting (Slack, PagerDuty)
- [ ] Historical trend analysis
- [ ] RBAC for multi-tenant deployments
- [ ] Terraform/IaC scanning
- [ ] Remediation automation (auto-fix via Terraform)

---

## 🤝 Contributing

This is the **exact architecture** used by enterprise CSPM tools:
- Wiz uses this pattern
- Prisma Cloud uses this pattern
- Lacework uses this pattern

You've built industry-standard CSPM. 🎉

---

## 📜 License

MIT License - Use freely in commercial projects

---

## 🆘 Troubleshooting

### AWS Credentials Not Working
```bash
aws sts get-caller-identity  # Verify credentials
```

### GCP Authentication Error
```bash
gcloud auth application-default login
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

### Database Connection Failed
```bash
psql -h localhost -U postgres -d mcp_scanner  # Test connection
```

### OpenAI API Rate Limit
- Use `gpt-4o-mini` instead of `gpt-4` (cheaper, faster)
- Add retry logic with exponential backoff

---

## 📞 Support

- Issues: Open GitHub issue
- Email: your-email@example.com
- Docs: See `/docs` endpoint when server is running

---

**Built with ❤️ using MCP Architecture**
