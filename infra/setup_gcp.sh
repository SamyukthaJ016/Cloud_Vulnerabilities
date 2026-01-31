#!/bin/bash

# CloudGuard GCP Setup Script
# Automatically enables APIs and configures permissions for the scanner.

set -e

# Configuration
SERVICE_ACCOUNT_NAME="cloudguard-scanner"
DISPLAY_NAME="CloudGuard Vulnerability Scanner"
PROJECT_ID=$(gcloud config get-value project)
KEY_FILE="gcp-service-account.json"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: 'gcloud' CLI is not installed."
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

echo "🚀 Starting CloudGuard GCP Setup for project: $PROJECT_ID"
echo "--------------------------------------------------------"

# 1. Enable Required APIs
echo "📡 Enabling required APIs..."
gcloud services enable \
    cloudresourcemanager.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com \
    iam.googleapis.com \
    --project "$PROJECT_ID"
echo "✅ APIs enabled."

# 2. Create Service Account
echo "👤 Creating Service Account: $SERVICE_ACCOUNT_NAME..."
if gcloud iam service-accounts describe "$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com" --project "$PROJECT_ID" &> /dev/null; then
    echo "   Service account already exists, skipping creation."
else
    gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" \
        --description "$DISPLAY_NAME" \
        --display-name "$DISPLAY_NAME" \
        --project "$PROJECT_ID"
    echo "✅ Service account created."
fi

# 3. Assign Roles
echo "🔑 Assigning IAM Roles..."
SA_EMAIL="$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"

# Viewer (Basic read access)
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/viewer" \
    --condition=None \
    --quiet > /dev/null
echo "   - Assigned 'Viewer' role"

# Security Reviewer (IAM policy analysis)
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/iam.securityReviewer" \
    --condition=None \
    --quiet > /dev/null
echo "   - Assigned 'Security Reviewer' role"

echo "✅ Permissions granted."

# 4. Generate Key
echo "📥 Generating JSON Key..."
if [ -f "$KEY_FILE" ]; then
    echo "   ⚠️  Key file '$KEY_FILE' already exists. Skipping download to prevent overwrite."
else
    gcloud iam service-accounts keys create "$KEY_FILE" \
        --iam-account="$SA_EMAIL" \
        --project "$PROJECT_ID"
    echo "✅ Key saved to: $PWD/$KEY_FILE"
fi

echo "--------------------------------------------------------"
echo "🎉 Setup Complete!"
echo ""
echo "NEXT STEPS:"
echo "1. The credentials file '$KEY_FILE' is ready."
echo "2. Use this file to configure the scanner in the Dashboard or .env file."
echo "--------------------------------------------------------"
