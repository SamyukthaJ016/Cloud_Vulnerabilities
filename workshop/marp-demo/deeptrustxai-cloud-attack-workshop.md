---
marp: true
theme: deeptrustxai
paginate: true
html: true
title: DeepTrustxAI Cloud Attack Paths and Evidence-Driven Defense Workshop
description: Two-day authorized lab workshop covering multi-cloud attack paths, scanner evidence, connectors, tenant isolation, and GRC outcomes.
header: '![DeepTrustxAI](images/deeptrustxai-logo.png) **DeepTrustxAI**'
footer: 'DeepTrustxAI | Cloud Attack Paths and Evidence-Driven Defense'
---

<!-- _class: lead -->
<!-- _header: '' -->
<!-- _footer: '' -->
<!-- _paginate: false -->

<div class="brand-lockup">
  <img src="images/deeptrustxai-logo.png" alt="DeepTrustxAI logo">
  <span class="brand-name">DeepTrustxAI</span>
</div>

# Cloud Attack Paths and Evidence-Driven Defense

## Two-day authorized multi-cloud security workshop

AWS · Azure · GCP · DigitalOcean · Kubernetes · IaC · CI/CD · GRC

---

# Workshop Promise

<div class="grid-3">
  <div class="card cyan"><h3>Think in attack paths</h3><p>Connect exposure, identity, workload, data, and control-plane impact.</p></div>
  <div class="card violet"><h3>Prove with evidence</h3><p>Compare manual lab observations with scanner and connector output.</p></div>
  <div class="card green"><h3>Finish with controls</h3><p>Map findings to owners, remediation, control status, and closure proof.</p></div>
</div>

> The goal is not to collect more findings. The goal is to explain the most important path, prove it safely, and close it permanently.

---

# Learning Outcomes

By the end of the workshop, participants can:

- Explain a multi-step cloud attack path without relying on provider jargon.
- Identify high-risk weaknesses across IAM, storage, metadata, serverless, data, Kubernetes, IaC, CI/CD, and AI automation.
- Validate a condition inside an **authorized disposable lab** and compare it with scanner output.
- Normalize evidence using a connector contract with `tenant_id` and scan lineage.
- Convert findings into control status, remediation ownership, and audit-ready proof.
- Deliver a five-minute leadership briefing focused on business impact and action.

---

# Format and Team Roles

| Item | Workshop design |
|---|---|
| Duration | 2 days, 8 hours per day including breaks |
| Level | Intermediate to advanced |
| Delivery | Instructor-led, lab-heavy, team-based |
| Lab model | Disposable accounts/projects, namespaces, and local clusters only |
| Team roles | Cloud operator, investigator, evidence owner, dashboard owner, presenter |
| Final output | Attack path, evidence bundle, scanner validation, control mapping, remediation brief |

---

<!-- _class: safety -->

# Rules of Engagement

- Use only the target list and tenant assigned by the instructor.
- Do not scan public targets, third-party systems, personal accounts, or production environments.
- Stop immediately when an asset falls outside the documented lab boundary.
- Never place a real production secret inside a vulnerable fixture.
- Capture only the evidence needed; redact tokens, personal data, and sensitive values.
- Keep budgets, quotas, expiry tags, and cleanup workers active.
- Rotate or destroy lab credentials after completion.

> If it is not owned, isolated, approved, and recoverable, it is not a workshop target.

---

# Training Lab Architecture

<div class="flow">
  <div class="step"><strong>Vulnerable Lab</strong><span>Isolated cloud account, project, namespace, or IaC bundle</span></div>
  <div class="step"><strong>Scanner Worker</strong><span>AWS, GCP, Kubernetes, IaC, web, secret, or dependency workflow</span></div>
  <div class="step"><strong>Connector</strong><span>Normalize source output and preserve scan lineage</span></div>
  <div class="step"><strong>Evidence Processor</strong><span>Validate tenant, deduplicate, store artifact, map controls</span></div>
  <div class="step"><strong>GRC Dashboard</strong><span>Risk, owner, status, remediation, and audit proof</span></div>
</div>

<div class="grid-3 small">
  <div class="card cyan"><h3>Decoupled</h3><p>Heavy scans run separately from the portal.</p></div>
  <div class="card violet"><h3>Tenant-aware</h3><p>Jobs, findings, evidence, assets, and credentials carry tenant context.</p></div>
  <div class="card amber"><h3>Recoverable</h3><p>Labs have reset, teardown, budget, and TTL controls.</p></div>
</div>

---

# Common Evidence Contract

```json
{
  "tenant_id": "tenant_demo_001",
  "source_system": "aws_scanner",
  "scanner_type": "cloud",
  "scan_job_id": "scan_001",
  "asset_id": "aws:s3:::lab-artifacts",
  "finding_id": "public_storage_001",
  "severity": "high",
  "control_ids": ["DATA-04", "IAM-02"],
  "evidence_type": "policy_snapshot",
  "evidence_uri": "evidence://tenant_demo_001/scan_001/policy.json",
  "status": "open",
  "remediation": "Restrict public access and require explicit principals."
}
```

**Never include raw credentials in findings.** Store an encrypted tenant-scoped credential reference instead.

---

# Two-Day Module Plan

| Day 1: Exposure to identity | Day 2: Platform depth to governance |
|---|---|
| M0 Orientation and setup | M6 Containers and Kubernetes |
| M1 Multi-cloud attack-path mindset | M7 IAM escalation graph |
| M2 Recon to first foothold | M8 Provider-specific kill chains |
| M3 Storage and artifact exposure | M9 CI/CD, developer platforms and AI |
| M4 SSRF, metadata and identity | M10 Defenses that work |
| M5 Serverless and data tier | Capstone investigation and briefing |

---

<!-- _class: module -->

<div class="module-number">00</div>

# Orientation and Setup

## Confirm authorization, tenant routing, and the end-to-end evidence workflow

30 minutes · Portal walkthrough · Dry-run job · Evidence validation

---

<!-- _class: exercise -->

# Module 0 Lab: Prove Tenant Routing

| Phase | Participant action | Expected evidence |
|---|---|---|
| Scope | Confirm assigned tenant and disposable lab ID | Scope acknowledgement |
| Queue | Trigger a dry-run scan job | `scan_job.created` |
| Ingest | Submit a sample evidence record | `evidence.accepted` |
| Isolate | Attempt lookup using another training tenant | Access denied or no result |
| Verify | Open the compliance/evidence view | Correct tenant and control context |

**Success condition:** job, finding, artifact, and audit event all resolve to the same `tenant_id`.

---

<!-- _class: module -->

<div class="module-number">01</div>

# Multi-Cloud Attack-Path Mindset

## Model cloud compromises as connected control failures

60 minutes · Attack graph · Scanner detection points · Control mapping

---

# Anatomy of a Cloud Attack Path

<div class="flow">
  <div class="step"><strong>Exposure</strong><span>Public asset, leaked artifact, vulnerable app, or weak trust</span></div>
  <div class="step"><strong>Identity</strong><span>User, role, service account, managed identity, or token</span></div>
  <div class="step"><strong>Privilege</strong><span>Broad action, trust edge, role chain, or automation capability</span></div>
  <div class="step"><strong>Target</strong><span>Data store, secret, workload, pipeline, or control-plane resource</span></div>
  <div class="step"><strong>Impact</strong><span>Disclosure, persistence, service disruption, or governance failure</span></div>
</div>

> A useful finding explains where the path starts, which identity moves it forward, and what evidence proves the blast radius.

---

<!-- _class: exercise -->

# Module 1 Exercise: Build the Graph

Teams receive a short breach story and produce:

<div class="grid-2">
  <div class="card cyan"><h3>Technical graph</h3><p>Entry point, identity, privilege edge, target, impact, and missing detection.</p></div>
  <div class="card violet"><h3>Evidence map</h3><p>API response, policy snapshot, log event, scanner finding, artifact hash, and owner.</p></div>
</div>

### Discussion prompts

- Which single control would break the largest number of edges?
- Which scanner should have detected the path earliest?
- What would an auditor need to verify closure?

---

<!-- _class: module -->

<div class="module-number">02</div>

# Recon to First Foothold

## Find inventory gaps and intentional exposure only inside assigned lab scope

90 minutes · Asset inventory · Manual proof · Scanner comparison

---

# Recon Evidence Model

<div class="grid-3">
  <div class="card cyan"><h3>Inventory</h3><p>Asset identifier, provider, region, owner, environment, and expected exposure.</p></div>
  <div class="card amber"><h3>Observation</h3><p>Service response, policy state, DNS record, or artifact class without collecting secrets.</p></div>
  <div class="card violet"><h3>Validation</h3><p>Scanner finding, duplicate handling, false-positive note, severity, and control mapping.</p></div>
</div>

### Lab targets may include

- Public object storage configured for the exercise
- Exposed test service or debug endpoint
- Stale test DNS record
- Lab-only build artifact
- Asset absent from the expected inventory

---

<!-- _class: exercise -->

# Module 2 Lab: Manual vs Scanner

| Step | Action | Output |
|---|---|---|
| 1 | Enumerate only assigned lab assets | Asset list |
| 2 | Record intended and unintended exposure | Observation worksheet |
| 3 | Capture redacted proof | Screenshot or API artifact |
| 4 | Run the cloud inventory scanner | Finding export |
| 5 | Reconcile misses, duplicates, and severity | Validation notes |

**Control question:** was the root cause missing inventory, incorrect configuration, or excessive identity access?

---

<!-- _class: module -->

<div class="module-number">03</div>

# Storage and Artifact Exposure

## Trace how buckets, backups, logs, and build artifacts expose sensitive material

75 minutes · Policy review · Artifact classification · Remediation diff

---

# Storage Risk Patterns

<div class="grid-4">
  <div class="card cyan"><h3>Public access</h3><p>Anonymous or internet-wide read/list permissions.</p></div>
  <div class="card violet"><h3>Cross-tenant trust</h3><p>Broad principals or shared credentials beyond intended scope.</p></div>
  <div class="card amber"><h3>Artifact leakage</h3><p>Backups, logs, source maps, environment files, or build output.</p></div>
  <div class="card red"><h3>Weak evidence handling</h3><p>Raw sensitive material copied into tickets or chat.</p></div>
</div>

### Durable controls

Default-deny access · Explicit principals · Encryption · Retention rules · Secret scanning · Evidence redaction

---

<!-- _class: exercise -->

# Module 3 Lab: Policy to Proof

| Phase | Participant action | Evidence produced |
|---|---|---|
| Review | Inspect the prepared vulnerable storage configuration | Policy snapshot |
| Classify | Identify artifact type without exposing its value | Data-classification label |
| Detect | Compare manual result with scanner finding | Finding and lineage |
| Fix | Draft or apply least-privilege access | Remediation diff |
| Prove | Rescan and record new state | Closure evidence |

**Do not copy sensitive artifact content.** Use metadata, hashes, and redacted samples.

---

<!-- _class: module -->

<div class="module-number">04</div>

# SSRF, Metadata and Cloud Identity

## Understand how an application weakness can become runtime-identity exposure

75 minutes · Controlled trace · Effective permissions · Shared ownership

---

# Controlled Application-to-Identity Path

<div class="flow">
  <div class="step"><strong>Application input</strong><span>Instructor-provided request path inside the lab</span></div>
  <div class="step"><strong>Internal reachability</strong><span>Application can reach a restricted metadata surface</span></div>
  <div class="step"><strong>Runtime identity</strong><span>Instance, workload, or managed identity becomes relevant</span></div>
  <div class="step"><strong>Effective permissions</strong><span>The attached role defines the actual blast radius</span></div>
  <div class="step"><strong>Control response</strong><span>App fix, metadata hardening, egress restriction, least privilege</span></div>
</div>

> The lab focuses on evidence and remediation, not exploitation of public applications.

---

# Module 4 Evidence and Ownership

<div class="grid-2">
  <div class="card red"><h3>Application owner</h3><p>Validate input handling, destination restrictions, redirects, and server-side request behavior.</p></div>
  <div class="card green"><h3>Cloud owner</h3><p>Harden metadata access, reduce runtime permissions, restrict egress, and monitor identity use.</p></div>
</div>

### Evidence bundle

- Redacted application route and expected behavior
- Metadata protection configuration
- Attached runtime identity
- Effective permission snapshot
- Scanner output and two-owner remediation ticket

---

<!-- _class: module -->

<div class="module-number">05</div>

# Serverless and Data Tier

## Identify lateral-movement risk in functions, queues, databases, and secrets stores

60 minutes · Function identity · Sensitive configuration · Control mapping

---

<!-- _class: exercise -->

# Module 5 Lab: Automation Identity Review

<div class="grid-3">
  <div class="card cyan"><h3>Function or job</h3><p>Trigger, attached identity, environment configuration, and deployment source.</p></div>
  <div class="card amber"><h3>Data path</h3><p>Database, queue, object store, or secret store reachable from the workload.</p></div>
  <div class="card violet"><h3>Evidence path</h3><p>Manual observation, scanner finding, control mapping, and closure proof.</p></div>
</div>

### Review questions

- Does the automation identity have more access than the trigger requires?
- Can sensitive values be moved out of environment variables or build logs?
- Is the data service reachable beyond the intended workload boundary?
- Which log or alert would detect abnormal use?

---

<!-- _class: module -->
<!-- _header: '' -->

<div class="module-number">DAY 2</div>

# Platform Depth to Governance

## Kubernetes, IAM graphs, provider equivalence, CI/CD, AI, controls, and capstone

Scanner validation becomes evidence, ownership, remediation, and executive proof.

---

<!-- _class: module -->

<div class="module-number">06</div>

# Containers and Kubernetes

## Assess workload, RBAC, network, secret, and drift risk in a disposable cluster

75 minutes · Kubeconfig scan · Live state · IaC comparison

---

# Kubernetes Scanner Coverage

| Area | Checks | Evidence |
|---|---|---|
| Workloads | Privileged mode, host mounts, risky capabilities, default namespace | Pod/deployment specification |
| Identity | Service accounts, Roles, ClusterRoles, bindings | Effective RBAC path |
| Network | LoadBalancer/NodePort exposure, missing NetworkPolicy | Service and policy snapshot |
| Secrets | Unnecessary mounts and broad namespace visibility | Redacted workload reference |
| Drift | Live state compared with YAML or Terraform intent | Deployment-to-IaC diff |

---

<!-- _class: exercise -->

# Module 6 Lab: Live Cluster to IaC

1. Connect using the assigned kubeconfig and context.
2. Inventory pods, services, namespaces, RBAC, and network policies.
3. Identify the prepared privileged workload and broad identity path.
4. Compare live objects with the provided IaC manifests.
5. Rank fixes by blast radius, operational impact, and proof requirement.

> Success is not “the scanner produced findings.” Success is a defensible priority order with evidence and owners.

---

<!-- _class: module -->

<div class="module-number">07</div>

# IAM Escalation Graph

## See permissions as graph edges and trust relationships

75 minutes · Identity graph · Dangerous edges · Least-privilege plan

---

# Identity Graph Thinking

<div class="flow">
  <div class="step"><strong>Principal</strong><span>User, workload, CI token, function, or service agent</span></div>
  <div class="step"><strong>Trust edge</strong><span>Assume, impersonate, bind, delegate, or pass</span></div>
  <div class="step"><strong>Action</strong><span>Create, update, attach, invoke, deploy, or modify policy</span></div>
  <div class="step"><strong>Resource scope</strong><span>Wildcard, project, subscription, account, namespace, or object</span></div>
  <div class="step"><strong>Impact</strong><span>Privilege expansion, persistence, secret access, or control-plane change</span></div>
</div>

**Graph edge fields:** principal · action · resource · condition · trust policy · exception reason

---

<!-- _class: exercise -->

# Module 7 Lab: Mark the Dangerous Edges

<div class="grid-2">
  <div class="card red"><h3>Investigation</h3><p>Build the identity graph, mark escalation edges, and identify the highest-impact reachable resource.</p></div>
  <div class="card green"><h3>Remediation</h3><p>Reduce action and resource scope, add conditions, preserve a documented break-glass path, and rescan.</p></div>
</div>

### Evidence produced

Identity graph · High-risk permission list · Scanner finding · Exception record · Least-privilege policy diff

---

<!-- _class: module -->

<div class="module-number">08</div>

# Provider-Specific Kill Chains

## Normalize the evidence, not the provider terminology

75 minutes · AWS · Azure · GCP · DigitalOcean · Developer platforms

---

# Equivalent Control Points

| Control area | AWS | Azure | GCP | DigitalOcean |
|---|---|---|---|---|
| Identity | IAM role/policy | Entra ID/managed identity | Project IAM/service account | Teams, projects, API tokens |
| Storage | S3 | Blob/storage account | Cloud Storage | Spaces |
| Runtime | EC2/Lambda/EKS | VM/Functions/AKS | Compute/Functions/GKE | Droplet/Functions/DOKS |
| Data | RDS/DynamoDB | Azure SQL/Cosmos DB | Cloud SQL/Firestore | Managed databases |
| Evidence | CloudTrail/config APIs | Activity logs/resource graph | Audit logs/asset inventory | API inventory/service logs |

---

<!-- _class: exercise -->

# Module 8 Exercise: Normalize Four Cases

For each provider mini-case, produce the same fields:

- Tenant and scan-job lineage
- Asset identifier and type
- Finding class and severity
- Identity or exposure root cause
- Evidence type and URI
- Control IDs
- Owner and remediation
- Closure proof requirement

> Provider-specific details belong in metadata. The control title should remain understandable across clouds.

---

<!-- _class: module -->

<div class="module-number">09</div>

# CI/CD, Developer Platforms and AI

## Treat automation platforms and agents as cloud-adjacent control planes

60 minutes · OIDC · Tokens · Artifacts · Deployment permissions · AI guardrails

---

# CI/CD Attack Surface

<div class="flow">
  <div class="step"><strong>Repository</strong><span>Workflow definition, branch control, secret references</span></div>
  <div class="step"><strong>Runner</strong><span>Build environment, logs, cache, artifacts, network access</span></div>
  <div class="step"><strong>Identity</strong><span>OIDC trust, deployment token, cloud role, service account</span></div>
  <div class="step"><strong>Platform</strong><span>Environment variables, project settings, deployment control</span></div>
  <div class="step"><strong>Cloud target</strong><span>Runtime, storage, registry, database, or cluster</span></div>
</div>

**Key checks:** token scope · OIDC audience/subject · protected branches · artifact visibility · deployment approval

---

# AI Integration Guardrails

<div class="grid-3">
  <div class="card red"><h3>Risk</h3><p>Agent receives broad cloud credentials, sensitive evidence, or direct scanner/deployment actions.</p></div>
  <div class="card green"><h3>Containment</h3><p>Private model endpoint when needed, tenant-scoped tools, redaction, action logs, and approval gates.</p></div>
  <div class="card amber"><h3>Cost</h3><p>Use small models for summaries, batch findings, cache outputs, and reserve larger models for complex reasoning.</p></div>
</div>

### Evidence to retain

Permission boundary · Approved action log · Redacted prompt · Artifact hash · Model/endpoint identifier · Human approval

---

<!-- _class: exercise -->

# Module 9 Lab: Workflow and Agent Review

| Phase | Participant action | Evidence produced |
|---|---|---|
| Inspect | Review the prepared workflow and deployment trust | Workflow snapshot |
| Scope | Identify token, OIDC, and cloud permission excess | Identity finding |
| Normalize | Submit a CI/CD connector payload | Accepted evidence record |
| Guard | Define AI tool permissions and approval rule | Boundary recommendation |
| Prove | Show the action log and tenant context | Audit evidence |

---

<!-- _class: module -->

<div class="module-number">10</div>

# Defenses That Actually Work

## Convert findings into prevention, detection, response, and proof

45 minutes · Control matrix · Remediation ticket · Rescan evidence

---

# Control and Evidence Matrix

| Layer | Required question | Workshop evidence |
|---|---|---|
| Prevent | What stops the weakness from being introduced? | Policy-as-code result, permission boundary, protected branch |
| Detect | What identifies the condition or abuse? | Scanner run, audit event, drift alert, anomaly detection |
| Respond | Who owns containment and remediation? | Ticket, severity, due date, exception, rollback or rotation |
| Prove | What demonstrates closure? | Before/after configuration, rescan, artifact checksum, approval |

> A control without an owner and evidence requirement is only a suggestion.

---

<!-- _class: module -->

<div class="module-number">CAPSTONE</div>

# End-to-End Investigation and Briefing

## Find the most important path, prove it, and explain how to close it

60 minutes · Team investigation · Evidence bundle · Five-minute presentation

---

# Capstone Scenario

A newly onboarded tenant contains intentional weaknesses across:

<div class="grid-4">
  <div class="card cyan"><h3>IaC</h3><p>Public exposure, broad IAM, weak labels, or privileged workload.</p></div>
  <div class="card violet"><h3>Cloud IAM</h3><p>Trust edge or excessive automation permission.</p></div>
  <div class="card amber"><h3>Storage and data</h3><p>Over-broad access or exposed lab artifact.</p></div>
  <div class="card red"><h3>Kubernetes/CI</h3><p>Broad RBAC, exposed service, drift, or deployment token risk.</p></div>
</div>

Teams must select the **highest-risk connected path**, not simply report every finding.

---

# Capstone Deliverables and Scoring

| Area | Points | What good looks like |
|---|---:|---|
| Attack path | 20 | Correct chain from exposure to impact |
| Evidence and tenant isolation | 20 | Redacted artifacts with lineage and correct `tenant_id` |
| Scanner validation | 20 | Manual proof reconciled with scanner findings |
| Control mapping | 15 | Findings linked to controls and accountable owners |
| Remediation | 15 | Practical fix with proof and exception handling |
| Executive briefing | 10 | Clear impact, priority, action, and residual risk |

---

# Instructor Preparation

<div class="grid-2 small">
  <div class="card cyan"><h3>Lab readiness</h3><p>Disposable accounts/projects, region restrictions, budgets, expiry tags, reset and teardown scripts.</p></div>
  <div class="card violet"><h3>Platform readiness</h3><p>Portal, database, object storage, queue, workers, connectors, and health checks.</p></div>
  <div class="card amber"><h3>Evidence fixtures</h3><p>Known-good scanner outputs, connector payloads, negative tenant tests, and redacted artifacts.</p></div>
  <div class="card green"><h3>Delivery fallback</h3><p>Prerecorded demos, sample evidence, solution guide, capstone answer, and scoring sheet.</p></div>
</div>

**Dry run:** complete the entire workshop at least three days before delivery.

---

# Student Pack

| Item | Included material |
|---|---|
| Lab guide | Authorized steps, scope boundaries, expected evidence, and stop conditions |
| Cheat sheets | Cloud CLI, kubectl, Terraform, evidence schema, severity guide |
| Connector examples | AWS, GCP, Kubernetes, IaC, CI/CD normalized payloads |
| Hardening checklist | Provider-specific controls mapped to finding classes |
| Cleanup guide | Resource teardown, credential rotation, cost check, audit export |
| Reporting templates | Attack path worksheet, remediation ticket, executive briefing |

---

# Delivery Rollout

<div class="grid-4">
  <div class="card cyan"><h3>Week 1</h3><p>Freeze syllabus, evidence schema, authorization model, and tenant boundaries.</p></div>
  <div class="card violet"><h3>Week 2</h3><p>Build and test AWS, GCP, Kubernetes, IaC, and CI/CD fixtures.</p></div>
  <div class="card amber"><h3>Week 3</h3><p>Run internal dry run with scanners, connectors, GRC, scoring, and cleanup.</p></div>
  <div class="card green"><h3>Week 4</h3><p>Deliver, collect feedback, export evidence, and create the improvement backlog.</p></div>
</div>

### Acceptance gates

All labs reset cleanly · No production dependency · Tenant tests pass · Evidence appears in GRC · Costs remain bounded

---

# Sources and Usage

- DeepTrustxAI logo: official brand asset from [deeptrustxai.com/images/darkmode.png](https://deeptrustxai.com/images/darkmode.png)
- Curriculum scope reference: public DEF CON Training listing for “Breaking the Cloud Layer - Modern and Practical Attacks on AWS, Azure, GCP, Aliyun, Railway and Vercel”
- CloudGuard project context: scanner workers, evidence connectors, compliance dashboard, tenant-aware architecture, and authorized vulnerable labs
- This deck is original internal training material and is restricted to approved lab environments

---

<!-- _class: closing -->
<!-- _header: '' -->
<!-- _footer: '' -->
<!-- _paginate: false -->

<div class="brand-lockup">
  <img src="images/deeptrustxai-logo.png" alt="DeepTrustxAI logo">
  <span class="brand-name">DeepTrustxAI</span>
</div>

# Find the Path. Prove the Risk. Close the Control.

## Scanner findings become useful when they carry tenant context, evidence, ownership, and remediation proof.
