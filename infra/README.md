# CloudFormation Template Upload

## Automatic Upload to S3

To automatically upload the enhanced CloudFormation template to your S3 bucket:

```bash
# Run the upload script
./scripts/upload-cfn-template.sh
```

This will:
1. ✅ Validate the CloudFormation template syntax
2. 📤 Upload to `s3://cloudguard-cfn-templates/cloudformation/aws-readonly-role.yaml`
3. 🔓 Set public read permissions
4. 📍 Display the public S3 URL
5. 🏷️ Keep created AWS resources tagged with `Owner=cloudvul@iitm`

## Manual Upload (Alternative)

If you prefer to upload manually:

```bash
# Upload to S3
aws s3 cp infra/enhanced-cloudformation-template.yaml \
  s3://cloudguard-cfn-templates/cloudformation/aws-readonly-role.yaml \
  --region eu-north-1 \
  --content-type "text/yaml" \
  --acl public-read

# Verify upload
aws s3 ls s3://cloudguard-cfn-templates/cloudformation/
```

## Template URL

After upload, the template will be available at:
```
https://cloudguard-cfn-templates.s3.eu-north-1.amazonaws.com/cloudformation/aws-readonly-role.yaml
```

## CI/CD Integration

Add to your deployment pipeline:

```yaml
# GitHub Actions example
- name: Upload CloudFormation Template
  run: ./scripts/upload-cfn-template.sh
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_DEFAULT_REGION: eu-north-1
```

## Troubleshooting

**Permission Denied**
```bash
chmod +x scripts/upload-cfn-template.sh
```

**AWS Credentials Not Configured**
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

**S3 Bucket Doesn't Exist**
```bash
# Create the bucket
aws s3 mb s3://cloudguard-cfn-templates --region eu-north-1

# Tag the bucket
aws s3api put-bucket-tagging \
  --bucket cloudguard-cfn-templates \
  --tagging '{"TagSet":[{"Key":"Owner","Value":"cloudvul@iitm"}]}'

# Enable public access (if needed)
aws s3api put-public-access-block \
  --bucket cloudguard-cfn-templates \
  --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```
