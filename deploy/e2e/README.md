# E2E Deployment

This deployment keeps the CloudGuard portal/GRC layer separate from heavy scanner execution.

## Target Layout

- **Portal VM:** dashboard, GRC module, FastAPI API, PostgreSQL, scheduler in enqueue-only mode, Caddy, and optional MinIO object storage.
- **Worker VM:** local scan workers that process queued jobs directly against the shared database.
- **Connector VM/Service:** file/API connectors that normalize evidence and push it to `/api/evidence`.

The portal does not execute scanner workloads in this model. It queues jobs and stores/display evidence.

## 1. Portal VM

Install Docker on the VM, then create an env file:

```bash
cp deploy/e2e/env.portal.example .env.e2e.portal
nano .env.e2e.portal
```

Start manually:

```bash
docker compose -f deploy/e2e/portal-compose.yml --env-file .env.e2e.portal up -d --build
```

Or deploy from your laptop:

```bash
./deploy/e2e/deploy.sh portal ubuntu@PORTAL_VM_IP .env.e2e.portal
```

## 2. Worker / Scanner VM

Create a worker env file:

```bash
cp deploy/e2e/env.worker.example .env.e2e.worker
nano .env.e2e.worker
```

Important:

- `DATABASE_URL` must point to the shared PostgreSQL database.
- `CONNECTOR_TOKEN` must match the portal env.
- Object storage settings should point to shared object storage. For separate VMs, prefer E2E object storage or MinIO exposed only on a private network.

Start manually:

```bash
docker compose -f deploy/e2e/worker-compose.yml --env-file .env.e2e.worker up -d --build
```

Or deploy from your laptop:

```bash
./deploy/e2e/deploy.sh worker ubuntu@WORKER_VM_IP .env.e2e.worker
```

## 3. Connector Contract

Connectors submit evidence to:

```text
POST /api/evidence
Header: x-connector-token: <CONNECTOR_TOKEN>
Header: x-cloudguard-user: <user-id>
```

Payload:

```json
{
  "evidence_id": "optional-id",
  "job_id": "optional-job-id",
  "control_id": "A.1.3.7",
  "control_name": "Enable access controls",
  "source_system": "trivy",
  "scanner_type": "container",
  "artifact_type": "json",
  "filename": "trivy-result.json",
  "content_type": "application/json",
  "payload": {
    "findings": []
  },
  "metadata": {
    "connector": "trivy-file"
  }
}
```

The bundled `evidence-connector` service watches `/app/connectors/inbox`. Any JSON file dropped there is normalized and posted to the portal.

## 4. Security Notes

- Do not expose PostgreSQL publicly. Use E2E private networking, firewall allowlists, or managed PostgreSQL.
- Do not expose MinIO publicly unless it is behind strict firewall rules.
- Rotate `WORKER_TOKEN` and `CONNECTOR_TOKEN` if they are shared.
- Keep scanner workers separate from the portal VM for production.
