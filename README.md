# CloudGuard Security Scanner

A comprehensive, containerized security scanning platform designed to identify vulnerabilities across cloud, Kubernetes, infrastructure-as-code, and application assets. The platform can run on DigitalOcean infrastructure while still scanning AWS, GCP, Kubernetes, and IaC targets when users provide credentials or files.

## 🚀 Features

- **Multi-Cloud Support**: Scans AWS, GCP, Kubernetes clusters, and IaC files.
- **DigitalOcean-Friendly Runtime**: Deploy the platform on a DigitalOcean Droplet with PostgreSQL, Caddy, worker containers, and Spaces-compatible evidence storage.
- **Web App Scanning**: Integrated OWASP ZAP and Nuclei for web vulnerability detection.
- **Secret Scanning**: Detects hardcoded secrets using Gitleaks.
- **Dependency Analysis**: Checks for vulnerable dependencies with Trivy and Safety.
- **Unified Dashboard**: View all findings in a single, easy-to-use web interface.
- **Dockerized**: Fully containerized for easy deployment.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- [Git](https://git-scm.com/)

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd Cloud_Vulnerabilities
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory. You can start by copying the example (if available) or ensuring you have the following keys:

```ini
# Database (PostgreSQL)
POSTGRES_USER=scanner_user
POSTGRES_PASSWORD=scanner_pass
POSTGRES_DB=scanner_db

# Redis
REDIS_PASSWORD=redis_password

# Application Secrets
SECRET_KEY=your-super-secret-key-change-this
ENCRYPTION_KEY=your-encryption-key

# Worker / Queue
QUEUE_BACKEND=postgres
WORKER_TOKEN=your-worker-token
SCAN_JOB_INLINE_WORKER=false

# Evidence storage on DigitalOcean Spaces
OBJECT_STORAGE_PROVIDER=digitalocean-spaces
OBJECT_STORAGE_ENDPOINT_URL=https://blr1.digitaloceanspaces.com
OBJECT_STORAGE_REGION=blr1
OBJECT_STORAGE_BUCKET=cloudguard-evidence
OBJECT_STORAGE_ACCESS_KEY_ID=your_spaces_key
OBJECT_STORAGE_SECRET_ACCESS_KEY=your_spaces_secret

# GCP Configuration (Optional)
GCP_PROJECT_ID=your_project_id
GCP_SERVICE_ACCOUNT_JSON=/app/config/gcp-service-account.json

# AI Analysis (Optional OpenAI-compatible endpoint)
AI_BASE_URL=http://your-model-host:11434/v1
AI_MODEL=llama3.1
AI_API_KEY=local-model
OPENAI_API_KEY=your_openai_key

# Public Deployment (HTTPS)
DOMAIN=your-domain.com
CADDY_EMAIL=you@example.com
```

### 3. Setup Cloud Permissions For Scan Targets
To scan a cloud account, add read-only credentials in the UI. AWS scanning still uses IAM/CloudFormation for target account access, but CloudGuard itself does not need to be hosted on AWS.
1. Navigate to the `infra/` folder.
2. Use the provided CloudFormation template or `iam_permissions.json` to configure an IAM Role or User with the necessary permissions.
   - See `infra/README.md` for detailed instructions on deploying the permissions stack.

## 🏃‍♂️ Usage

### Start the Application
Run the entire stack using Docker Compose:

```bash
docker compose up --build
```

This will start:
- **Backend API**: http://localhost:8000
- **Frontend Dashboard**: http://localhost:80
- **Database & Redis**: Background services

### Access the Dashboard
Open your browser and navigate to:
**[http://localhost](http://localhost)**

### Running a Scan
1. Log in to the dashboard.
2. Configure your target (URL, IP, or Cloud Account).
3. Click **"New Scan"**.
4. View real-time progress and detailed reports.

## 🏗️ Architecture

- **Frontend**: HTML/JS Dashboard (served via Nginx)
- **Backend**: FastAPI (Python)
- **Database**: PostgreSQL (Findings storage)
- **Queue**: PostgreSQL-backed `scan_jobs`
- **Tools**: Trivy, Gitleaks, Nuclei, CloudFox, OWASP ZAP

## 🛡️ Security Note

**Never commit your `.env` file.** It contains sensitive API keys and secrets. This repository includes a `.gitignore` to prevent accidental commits, but always double-check.

## 🌐 Deploy Online (Production + HTTPS)

This project includes a production profile with Caddy reverse proxy (automatic HTTPS).

For DigitalOcean, use the deployment guide in `deploy/digitalocean/README.md`:

```bash
cp .env.digitalocean.example .env
docker compose -f deploy/digitalocean/docker-compose.yml --env-file .env up -d --build
```

### 1. DNS + Firewall
- Point your domain `A` record to your server public IP.
- Open inbound ports: `80` and `443`.

### 2. Set deployment env vars
In your `.env` (or `.env.prod`) set:
- `DOMAIN=your-domain.com`
- `CADDY_EMAIL=you@example.com`
- `SECRET_KEY`, `ENCRYPTION_KEY`, cloud credentials, DB/Redis passwords

### 3. Start production stack
```bash
docker compose --profile prod up -d --build postgres redis backend caddy
```

### 4. Verify
```bash
docker compose --profile prod ps
curl -I https://your-domain.com
```

### 5. Security defaults included
- PostgreSQL port bound to localhost only.
- Redis port bound to localhost only.
- Backend is no longer exposed directly on host port in production.
