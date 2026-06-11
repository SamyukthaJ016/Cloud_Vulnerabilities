# AWS Scan Target Setup

This folder is only for customers who want CloudGuard to scan an AWS account. It is not required for hosting CloudGuard on DigitalOcean.

## CloudFormation Template Upload

The template can be uploaded to any public HTTPS location. AWS S3 is one option, but for a DigitalOcean-hosted platform you can also store the template in DigitalOcean Spaces or serve it from the app/static hosting.

## Recommended DigitalOcean Hosting

For a DigitalOcean deployment, place `enhanced-cloudformation-template.yaml` in a public DigitalOcean Space or serve it from the app/static hosting. The only requirement is a public HTTPS URL that AWS CloudFormation can fetch.

```bash
# Example with an S3-compatible CLI profile for DigitalOcean Spaces
aws --endpoint-url https://blr1.digitaloceanspaces.com s3 cp \
  infra/enhanced-cloudformation-template.yaml \
  s3://cloudguard-assets/cloudformation/aws-readonly-role.yaml \
  --content-type "text/yaml" \
  --acl public-read
```

The template URL will look like:

```text
https://cloudguard-assets.blr1.digitaloceanspaces.com/cloudformation/aws-readonly-role.yaml
```

## AWS S3 Alternative

If you already have an AWS bucket for scan-target setup assets, the old S3 flow still works. This is optional and is not part of CloudGuard hosting.

```bash
aws s3 cp infra/enhanced-cloudformation-template.yaml \
  s3://cloudguard-cfn-templates/cloudformation/aws-readonly-role.yaml \
  --region eu-north-1 \
  --content-type "text/yaml" \
  --acl public-read
```

## Template URL

Use the public template URL in the AWS scanner onboarding flow when creating a read-only role in the customer's AWS account.

## Validation

Validate the template before publishing:

```bash
aws cloudformation validate-template \
  --template-body file://infra/enhanced-cloudformation-template.yaml
```

## CI/CD Integration

DigitalOcean Spaces can be used from GitHub Actions with S3-compatible credentials:

```yaml
- name: Upload CloudFormation Template
  run: |
    aws --endpoint-url https://blr1.digitaloceanspaces.com s3 cp \
      infra/enhanced-cloudformation-template.yaml \
      s3://cloudguard-assets/cloudformation/aws-readonly-role.yaml \
      --content-type "text/yaml" \
      --acl public-read
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.DO_SPACES_KEY }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.DO_SPACES_SECRET }}
    AWS_DEFAULT_REGION: blr1
```

## Troubleshooting

**Permission denied**

```bash
chmod +x scripts/upload-cfn-template.sh
```

**Spaces credentials not configured**

```bash
aws configure --profile digitalocean-spaces
```

**AWS S3 bucket does not exist**

```bash
aws s3 mb s3://cloudguard-cfn-templates --region eu-north-1
```

**Public access blocked on an AWS S3 fallback bucket**

```bash
aws s3api put-public-access-block \
  --bucket cloudguard-cfn-templates \
  --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```
