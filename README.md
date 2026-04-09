# CloudGuard

CloudGuard is a multi-cloud security scanner with a FastAPI control plane, HTML dashboard, PostgreSQL-backed findings store, and optional worker-based execution for long-running scans.

It currently focuses on:

- AWS posture scanning
- GCP posture scanning
- Kubernetes cluster posture scanning
- AI-generated remediation summaries
- scan history, dashboard, schedules, and credential management

## What It Scans

### AWS

- S3 bucket exposure and hardening
- IAM user hygiene
- EC2 security group inventory
- CloudTrail coverage
- GuardDuty status
- VPC Flow Logs coverage
- optional CloudFox offensive enumeration

### GCP

- GCS bucket exposure and hardening
- Compute Engine instance posture
- project IAM policy risks
- firewall exposure

### Kubernetes

- namespaces, pods, services, ingresses, secrets, service accounts
- RBAC risks
- network policy coverage
- storage exposure patterns
- workload hardening issues
- optional Trivy image vulnerability scanning

## Main Technologies

- FastAPI
- PostgreSQL
- `boto3` / `botocore`
- Google Cloud Python clients
- Kubernetes Python client
- OpenAI API
- optional scanner binaries such as Trivy, Gitleaks, Nuclei, Grype, ZAP, and CloudFox

## Project Shape

This repo supports two main runtime shapes:

1. Local or VM-style deployment
   The FastAPI app runs directly and can execute scans itself.

2. Vercel control plane plus separate worker
   Vercel serves the UI and lightweight API routes, while a separate worker host runs heavy scans and scheduled work.

This second option is the recommended production setup for this repo.

## Authentication Modes

CloudGuard supports two auth modes:

- standalone mode
- external SSO mode

Standalone mode is used automatically when:

- `SSO_LOGIN_URL` is not set, or
- `SSO_LOGIN_URL` points back to the same app, or
- `CLOUDGUARD_AUTH_MODE=standalone`

In standalone mode, the app uses the built-in `anonymous` user flow and does not require a separate login app.

## Core Pages

- `/`
- `/dashboard`
- `/frontend/history.html`
- `/schedules`
- `/system-status`
- `/api/info`
- `/health`

## Environment Variables

Minimum variables for the app to boot:

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require
SECRET_KEY=replace-me
ENCRYPTION_KEY=replace-me
APP_ENV=development
LOG_LEVEL=INFO
```

Useful optional variables:

```env
OPENAI_API_KEY=
OPENAI_AGENT_MODEL=gpt-4o-mini
DEFAULT_AWS_REGION=ap-south-1
AWS_PROFILE=default
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
GCP_PROJECT_ID=
GCP_SERVICE_ACCOUNT_JSON=
CLOUDGUARD_AUTH_MODE=standalone
SSO_LOGIN_URL=
```

Worker-related variables:

```env
SCAN_WORKER_URL=https://your-worker.example.com
SCAN_WORKER_TOKEN=shared-secret
WORKER_API_TOKEN=shared-secret
```

## Local Python Run

1. Create and activate a virtual environment.
2. Install dependencies.
3. Point `DATABASE_URL` to a working PostgreSQL instance.
4. Start the FastAPI app.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Then open:

- [http://localhost:8000](http://localhost:8000)
- [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

## Local Worker Run

If you want the control plane to stay lightweight, run the worker separately:

```bash
export WORKER_API_TOKEN=replace-me
uvicorn backend.worker_app:app --host 0.0.0.0 --port 8010 --workers 2
```

Health check:

```bash
curl http://127.0.0.1:8010/health
```

## Docker Notes

Docker support is still present through [docker-compose.yml](docker-compose.yml), including:

- `backend-dev`
- `backend`
- `redis`
- `scheduler-worker`
- optional standalone `postgres`
- optional `caddy` reverse proxy

Because this repo has evolved toward a split control-plane and worker model, the Docker stack is best treated as a local or VM deployment option rather than the primary production target.

## Vercel Deployment

This repo is prepared for Vercel through:

- [index.py](index.py)
- [vercel.json](vercel.json)

Important:

- Vercel is a good fit for the UI and control plane
- Vercel is not a good fit for long-running scans or bundled scanner binaries
- use a separate worker for real scan execution

Detailed guide:

- [VERCEL_DEPLOY.md](VERCEL_DEPLOY.md)

## Worker Deployment

The worker runs:

- heavy multi-cloud scans
- manual schedule execution
- due-schedule processing
- binaries like CloudFox and Trivy that should not live in Vercel Functions

Detailed guide:

- [WORKER_DEPLOY.md](WORKER_DEPLOY.md)

Repo configs included for worker hosting:

- [render.worker.yaml](render.worker.yaml)
- [deploy/railway.worker.toml](deploy/railway.worker.toml)
- [deploy/railway.cron.toml](deploy/railway.cron.toml)
- [deploy/run-worker.sh](deploy/run-worker.sh)
- [deploy/run-due-schedules.sh](deploy/run-due-schedules.sh)

## Scanner Notes

### AWS Scanner

Implemented in [backend/mcp_servers/aws_server.py](backend/mcp_servers/aws_server.py).

Uses:

- `boto3`
- `STS AssumeRole`
- optional CloudFox

Default region in this repo is `ap-south-1`.

### GCP Scanner

Implemented in [backend/mcp_servers/gcp_server.py](backend/mcp_servers/gcp_server.py).

Uses:

- `google-cloud-storage`
- `google-cloud-compute`
- Google IAM / Resource Manager APIs

### Kubernetes Scanner

Implemented in [backend/mcp_servers/kubernetes_server.py](backend/mcp_servers/kubernetes_server.py).

Uses:

- Kubernetes Python client
- optional Trivy image scanning in deep-scan mode

## Current Production Guidance

Best practical setup:

- Vercel for the web app and API control plane
- managed PostgreSQL for storage
- a separate worker host for scans
- optional tunnel only for temporary local-worker testing

If your Kubernetes cluster or scanner binaries live on your laptop, the worker must also run somewhere that can reach them.

## Useful Docs In This Repo

- [VERCEL_DEPLOY.md](VERCEL_DEPLOY.md)
- [WORKER_DEPLOY.md](WORKER_DEPLOY.md)
- [infra/README.md](infra/README.md)

## Security Reminder

- do not commit real secrets
- do not commit production cloud credentials
- use least-privilege IAM and service-account access where possible
- prefer role assumption and managed secret storage for production
