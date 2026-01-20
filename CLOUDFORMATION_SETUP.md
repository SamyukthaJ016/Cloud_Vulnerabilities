# Quick Reference: CloudFormation Stack Deployment

## For Users

### How to Use the One-Click Setup

1. **Open Credentials Modal**
   - Click "🔐 Manage Credentials" in the dashboard
   - Navigate to the AWS tab

2. **Launch CloudFormation Stack**
   - Click "🚀 Launch CloudFormation Stack" button
   - AWS CloudFormation console will open in a new tab

3. **Create the Stack**
   - Review the permissions (all read-only)
   - Check the box: "I acknowledge that AWS CloudFormation might create IAM resources"
   - Click "Create stack"
   - Wait 2-3 minutes for completion

4. **Get the Role ARN**
   - Go to the "Outputs" tab of your stack
   - Copy the value of `RoleArn`

5. **Complete Setup**
   - Return to CloudGuard dashboard
   - Enter your AWS credentials in the manual form
   - Save credentials
   - Start scanning!

### Alternative: Manual Deployment

If you prefer to deploy via AWS CLI:

```bash
# Download the template
curl http://localhost:8000/api/credentials/aws/cloudformation-template -o cloudguard-role.yaml

# Deploy the stack
aws cloudformation create-stack \
  --stack-name CloudGuard-Scanner-MyAccount \
  --template-body file://cloudguard-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ScannerAccountId,ParameterValue=859561299880

# Wait for completion
aws cloudformation wait stack-create-complete \
  --stack-name CloudGuard-Scanner-MyAccount

# Get the Role ARN
aws cloudformation describe-stacks \
  --stack-name CloudGuard-Scanner-MyAccount \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' \
  --output text
```

---

## For Developers

### API Endpoints

**Get CloudFormation URL**
```bash
curl http://localhost:8000/api/credentials/aws/cloudformation-url
```

Response:
```json
{
  "cloudformation_url": "https://console.aws.amazon.com/cloudformation/...",
  "stack_name": "CloudGuard-Scanner-abc123",
  "region": "us-east-1",
  "template_url": null,
  "instructions": [...]
}
```

**Download Template**
```bash
curl http://localhost:8000/api/credentials/aws/cloudformation-template
```

### File Locations

- **Template**: `infra/enhanced-cloudformation-template.yaml`
- **Backend API**: `backend/credentials/api.py` (lines 451-541)
- **Frontend UI**: `frontend/credentials_modal.html` (lines 20-117)
- **JavaScript**: `frontend/credentials_modal.html` (lines 1441-1509)

### Permissions Included

The CloudFormation template grants read-only access to:

| Service | Actions |
|---------|---------|
| IAM | List/Get users, roles, policies, MFA devices |
| S3 | List buckets, get encryption, policies, ACLs |
| EC2/VPC | Describe instances, security groups, VPCs, flow logs |
| GuardDuty | List detectors, get findings |
| EBS | Describe volumes, snapshots, attributes |
| RDS | Describe instances, clusters, snapshots |
| ELB | Describe load balancers, listeners, SSL policies |
| Lambda | List/Get functions, configurations, policies |
| CloudTrail | Describe trails, get status, event selectors |
| CloudWatch | Describe log groups, metric filters |
| KMS | List keys, describe keys, get rotation status |
| AMI | Describe images and attributes |
| Secrets Manager | List/Describe secrets, get policies |
| Inspector | List findings, get account status |

---

### ⚠️ CRITICAL: ScannerAccountId Parameter

When deploying the template, you **MUST** ensure the `ScannerAccountId` parameter matches the account where the scanner is running.

- **One-Click Setup**: Automatically detects and pre-fills your Account ID.
- **Manual CLI**: Replace `YOUR_ACCOUNT_ID` with your 12-digit AWS Account ID.

```bash
# Example for manual deployment
aws cloudformation create-stack \
  --stack-name CloudGuard-Scanner \
  --template-body file://cloudguard-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ScannerAccountId,ParameterValue=YOUR_ACCOUNT_ID
```

---

## 🛠️ Fixing Existing Stacks (Trust Relationship Error)

If you've already deployed the stack but get "AccessDenied" when scanning, it's likely a **Trust Relationship mismatch**. Run this command to fix it instantly (replace `ROLE_NAME` and `YOUR_ACCOUNT_ID`):

```bash
aws iam update-assume-role-policy \
  --role-name CloudGuardReadOnlyRole-XXXXXX \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "CloudGuard-Scanner-Validation"}}
    }]
  }'
```

---

## Troubleshooting

### "AccessDenied" when scanning
Even if you added the identity policy, you might see this.
- **CAUSE**: The Role doesn't trust your Account ID.
- **SOLUTION**: Run the `update-assume-role-policy` command above or delete and redeploy the stack using the **One-Click Setup** (which now auto-detects your ID).

### Popup Blocked
If the CloudFormation console doesn't open:
1. Allow popups for this site
2. Click the launch button again

---

## Security Notes

✅ **Read-Only Access**: The role can only read configurations, not modify them.

✅ **Automated Repair**: The CloudGuard dashboard now features an **"Admin-Assisted Fix"** that can automatically repair both Identity and Trust policies if you provide admin keys.

✅ **Account-Aware Deployment**: Our Launch button now pre-fills your Account ID to prevent Trust Relationship errors.
