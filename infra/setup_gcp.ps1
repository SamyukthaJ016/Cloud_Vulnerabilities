<#
.SYNOPSIS
    CloudGuard GCP Setup Script (PowerShell)
    Automatically enables APIs and configures permissions for the scanner.

.DESCRIPTION
    This script checks for the gcloud CLI, enables required GCP APIs,
    creates a service account (if not exists), assigns Viewer and Security Reviewer roles,
    and generates a JSON key file for authentication.
#>

$ErrorActionPreference = "Stop"

# Configuration
$SERVICE_ACCOUNT_NAME = "cloudguard-scanner"
$DISPLAY_NAME = "CloudGuard Vulnerability Scanner"
$KEY_FILE = "gcp-service-account.json"

# Check if gcloud is installed
if (-not (Get-Command "gcloud" -ErrorAction SilentlyContinue)) {
    Write-Error "❌ Error: 'gcloud' CLI is not installed."
    Write-Host "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
}

# Get current project
try {
    $PROJECT_ID = gcloud config get-value project 2>$null
} catch {
    Write-Error "❌ Failed to get current GCP project. Please run 'gcloud init' or 'gcloud config set project <PROJECT_ID>'."
    exit 1
}

if (-not $PROJECT_ID) {
    Write-Error "❌ No GCP project selected. Please run 'gcloud config set project <PROJECT_ID>'."
    exit 1
}

Write-Host "🚀 Starting CloudGuard GCP Setup for project: $PROJECT_ID"
Write-Host "--------------------------------------------------------"

# 1. Enable Required APIs
Write-Host "📡 Enabling required APIs..."
gcloud services enable `
    cloudresourcemanager.googleapis.com `
    compute.googleapis.com `
    storage.googleapis.com `
    iam.googleapis.com `
    --project "$PROJECT_ID"
Write-Host "✅ APIs enabled."

# 2. Create Service Account
Write-Host "👤 Creating Service Account: $SERVICE_ACCOUNT_NAME..."
$SA_EMAIL = "$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"
$SA_EXISTS = $false

try {
    gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" 2>$null | Out-Null
    $SA_EXISTS = $true
} catch {
    $SA_EXISTS = $false
}

if ($SA_EXISTS) {
    Write-Host "   Service account already exists, skipping creation."
} else {
    gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" `
        --description "$DISPLAY_NAME" `
        --display-name "$DISPLAY_NAME" `
        --project "$PROJECT_ID"
    Write-Host "✅ Service account created."
}

# 3. Assign Roles
Write-Host "🔑 Assigning IAM Roles..."

# Viewer (Basic read access)
gcloud projects add-iam-policy-binding "$PROJECT_ID" `
    --member="serviceAccount:$SA_EMAIL" `
    --role="roles/viewer" `
    --condition=None `
    --quiet | Out-Null
Write-Host "   - Assigned 'Viewer' role"

# Security Reviewer (IAM policy analysis)
gcloud projects add-iam-policy-binding "$PROJECT_ID" `
    --member="serviceAccount:$SA_EMAIL" `
    --role="roles/iam.securityReviewer" `
    --condition=None `
    --quiet | Out-Null
Write-Host "   - Assigned 'Security Reviewer' role"

Write-Host "✅ Permissions granted."

# 4. Generate Key
Write-Host "📥 Generating JSON Key..."
if (Test-Path "$KEY_FILE") {
    Write-Host "   ⚠️  Key file '$KEY_FILE' already exists. Skipping download to prevent overwrite."
} else {
    gcloud iam service-accounts keys create "$KEY_FILE" `
        --iam-account="$SA_EMAIL" `
        --project "$PROJECT_ID"
    Write-Host "✅ Key saved to: $(Get-Location)\$KEY_FILE"
}

Write-Host "--------------------------------------------------------"
Write-Host "🎉 Setup Complete!"
Write-Host ""
Write-Host "NEXT STEPS:"
Write-Host "1. The credentials file '$KEY_FILE' is ready."
Write-Host "2. Use this file to configure the scanner in the Dashboard or .env file."
Write-Host "--------------------------------------------------------"
