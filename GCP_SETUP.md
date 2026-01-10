# GCP Security Scanning Setup Guide

To enable full GCP security scanning in CloudGuard, you must provide valid GCP credentials and a Project ID.

## Prerequisites

1.  **GCP Service Account**: Create a service account in your GCP console.
2.  **Permissions**: Assign the `Viewer` role (or specific `storage.viewer`, `compute.viewer`, and `iam.viewer` roles) to the service account.
3.  **JSON Key**: Download the service account JSON key file.

## Configuration

There are two ways to configure GCP credentials in CloudGuard:

### 1. via Dashboard (Recommended)

1.  Navigate to the **Credentials** section on the CloudGuard dashboard.
2.  Select **GCP** as the provider.
3.  Paste the contents of your **Service Account JSON** and enter your **Project ID**.
4.  Save the credentials.

### 2. via Environment Variables (Local Development)

If you are running the backend locally for development, you can set the following environment variables:

- `GCP_PROJECT_ID`: Your GCP Project ID.
- `GCP_SERVICE_ACCOUNT_JSON`: Path to your service account JSON file OR the JSON string itself.

## Troubleshooting "Network is unreachable"

If you encounter a `Network is unreachable` error during GCP firewall scanning:

- **Check Credentials**: Ensure that you have provided a valid Service Account JSON. If missing, the scanner will attempt to use "Application Default Credentials" (metadata server), which fails on local machines.
- **Project ID Mismatch**: Ensure the `Project ID` provided matches the one in your JSON key.
- **API Permissions**: Ensure the **Compute Engine API** and **Cloud Storage API** are enabled in your GCP project.
