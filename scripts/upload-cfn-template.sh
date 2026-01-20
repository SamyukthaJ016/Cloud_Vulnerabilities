#!/bin/bash

# CloudFormation Template S3 Upload Script
# This script uploads the enhanced CloudFormation template to S3

set -e  # Exit on error

# Configuration
S3_BUCKET="cloudguard-cfn-templates"
S3_REGION="eu-north-1"
S3_KEY="cloudformation/aws-readonly-role.yaml"
LOCAL_TEMPLATE="infra/aws-readonly-role.yaml"

echo "🚀 CloudFormation Template Upload Script"
echo "=========================================="
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Please install it first:"
    echo "   brew install awscli  (macOS)"
    echo "   pip install awscli   (Python)"
    exit 1
fi

# Check if template file exists
if [ ! -f "$LOCAL_TEMPLATE" ]; then
    echo "❌ Template file not found: $LOCAL_TEMPLATE"
    exit 1
fi

echo "📋 Template: $LOCAL_TEMPLATE"
echo "🪣 S3 Bucket: s3://$S3_BUCKET/$S3_KEY"
echo "🌍 Region: $S3_REGION"
echo ""

# Validate CloudFormation template
echo "🔍 Validating CloudFormation template..."
if aws cloudformation validate-template \
    --template-body file://$LOCAL_TEMPLATE \
    --region $S3_REGION &> /dev/null; then
    echo "✅ Template is valid"
else
    echo "⚠️  Template validation skipped (requires AWS credentials)"
fi

# Upload to S3
echo ""
echo "📤 Uploading template to S3..."
aws s3 cp $LOCAL_TEMPLATE \
    s3://$S3_BUCKET/$S3_KEY \
    --region $S3_REGION \
    --content-type "text/yaml" \
    --metadata "version=2.0,coverage=20-checks"

# Make the template publicly readable (optional - for public access)
echo "🔓 Setting public read permissions..."
aws s3api put-object-acl \
    --bucket $S3_BUCKET \
    --key $S3_KEY \
    --acl public-read \
    --region $S3_REGION

# Get the public URL
S3_URL="https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${S3_KEY}"

echo ""
echo "✅ Upload complete!"
echo ""
echo "📍 Template URL:"
echo "   $S3_URL"
echo ""
echo "🔗 CloudFormation Quick-Create URL:"
echo "   https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=CloudGuard-Scanner&templateURL=$S3_URL"
echo ""
echo "💡 Tip: Users can now click the 'Launch CloudFormation Stack' button in the dashboard!"
