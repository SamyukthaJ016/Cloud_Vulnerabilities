# DeepTrustxAI Four-Day Cloud and Kubernetes Security Training

## Programme Structure

This programme is delivered as two independent tracks:

1. **Cloud Security Foundations, Vulnerabilities and CloudGuard** - 2 days
2. **Kubernetes Security Foundations, Vulnerabilities and CloudGuard** - 2 days

The cloud track can be delivered on its own. The Kubernetes track assumes participants understand basic cloud, Linux, networking, IAM, and containers, but it begins with Kubernetes fundamentals before security testing.

## Certification Mapping Basis

### CISSP Domains

- D1 Security and Risk Management
- D2 Asset Security
- D3 Security Architecture and Engineering
- D4 Communication and Network Security
- D5 Identity and Access Management
- D6 Security Assessment and Testing
- D7 Security Operations
- D8 Software Development Security

### CCSP Domains

- D1 Cloud Concepts, Architecture and Design
- D2 Cloud Data Security
- D3 Cloud Platform and Infrastructure Security
- D4 Cloud Application Security
- D5 Cloud Security Operations
- D6 Legal, Risk and Compliance

The CCSP mapping reflects the ISC2 outline available on 20 June 2026. ISC2 has announced a revised CCSP exam outline effective 1 August 2026; the module mapping should be reviewed against that outline before certification-focused delivery after that date.

# Track A: Cloud Security - Two Days

## Track Objectives

Participants will be able to:

- Explain cloud service, deployment, responsibility, identity, network, compute, storage, data, and management-plane concepts.
- Recognize how cloud vulnerabilities arise from configuration drift, excessive privilege, public exposure, weak secrets handling, and missing monitoring.
- Model vulnerabilities as connected attack paths rather than isolated findings.
- Run authorized AWS, GCP, IaC, web, secret, and dependency scan workflows.
- Explain how CloudGuard separates the portal, scanner workers, evidence connectors, and GRC reporting.
- Map findings to tenant, asset, evidence, control, owner, remediation, and closure proof.

## Cloud Day 1: Foundations and Secure Architecture

| Time | Module | Focus | CISSP | CCSP |
|---|---|---|---|---|
| 09:00-09:30 | C0 Orientation and lab setup | Authorization, tenants, CloudGuard workflow | D1, D6 | D5, D6 |
| 09:30-10:45 | C1 Cloud computing basics | Service/deployment models, shared responsibility, planes and regions | D1, D3 | D1, D3 |
| 11:00-12:15 | C2 Cloud identity and access | Human/workload identities, federation, roles, keys and least privilege | D5 | D1, D3, D5 |
| 13:15-14:30 | C3 Network, compute and storage | VPC/VNet, segmentation, endpoints, virtual compute and object storage | D2, D3, D4 | D2, D3 |
| 14:45-15:45 | C4 Data security and resilience | Data lifecycle, encryption, secrets, backup, RTO/RPO | D2, D3, D7 | D2, D3, D5 |
| 15:45-17:00 | C5 Secure architecture and IaC | Landing zones, guardrails, logging, IaC and configuration baselines | D1, D3, D7, D8 | D1, D3, D4, D5 |

## Cloud Day 2: Vulnerabilities and How CloudGuard Helps

| Time | Module | Focus | CISSP | CCSP |
|---|---|---|---|---|
| 09:00-10:15 | C6 How cloud vulnerabilities creep in | Misconfiguration lifecycle, drift, shadow assets and ownership gaps | D1, D6, D7, D8 | D3, D4, D5, D6 |
| 10:30-11:45 | C7 Identity, exposure and metadata attack paths | Excess privilege, public access, trust edges, metadata and automation | D3, D4, D5 | D1, D3, D4 |
| 12:45-13:45 | C8 Provider-specific patterns | AWS, GCP, Azure and DigitalOcean control equivalence | D3, D4, D5 | D1, D2, D3 |
| 13:45-15:00 | C9 CloudGuard scanners and job flow | Scanner coverage, credentials, queue, workers and operations | D6, D7 | D3, D5 |
| 15:15-16:00 | C10 Evidence connectors and GRC | Normalization, tenant isolation, control mapping and remediation | D1, D2, D6, D7 | D2, D5, D6 |
| 16:00-17:00 | C11 Cloud capstone | Investigate, scan, ingest, prioritize and brief | D1-D7 | D1-D6 |

## Cloud Module Details

### C0 Orientation and Lab Setup

**Objective:** Confirm authorization, assigned tenant, disposable lab environment, and evidence workflow.

**Topics:**

- Rules of engagement and stop conditions
- CloudGuard portal, scan jobs, workers, connectors, evidence store and GRC
- Tenant-scoped jobs, credentials, assets, findings and reports

**Exercise:** Trigger a dry-run scan, ingest sample evidence, and verify tenant separation.

### C1 Cloud Computing Basics

**Objective:** Build a common vocabulary before discussing vulnerabilities.

**Topics:**

- IaaS, PaaS, SaaS and serverless
- Public, private, hybrid and multi-cloud deployment models
- Regions, availability zones, edge locations and fault domains
- Shared responsibility and inherited controls
- Control plane, management plane, data plane and workload plane
- Virtualization, elasticity, automation, APIs and metering

**Exercise:** Classify twelve responsibilities between customer, provider, and shared ownership.

### C2 Cloud Identity and Access

**Objective:** Understand cloud identity as the primary security boundary.

**Topics:**

- Human users, groups, roles and federation
- Workload identities, service accounts and managed identities
- Authentication versus authorization
- Temporary credentials versus long-lived keys
- RBAC, ABAC, policy conditions and least privilege
- Privileged access, break-glass and access review

**Exercise:** Review a permission set, identify broad actions/resources, and produce a least-privilege revision.

### C3 Network, Compute and Storage

**Objective:** Understand the building blocks whose configuration creates or reduces exposure.

**Topics:**

- Virtual networks, subnets, routes, security groups and network ACLs
- Public/private endpoints, gateways, load balancers and DNS
- Virtual machines, images, containers, functions and metadata services
- Object, block, file, database and ephemeral storage
- Encryption in transit and at rest

**Exercise:** Draw the intended traffic path for a three-tier cloud application and identify its trust boundaries.

### C4 Data Security and Resilience

**Objective:** Apply data lifecycle, protection, retention and availability concepts to cloud services.

**Topics:**

- Data classification, location, ownership and lifecycle
- Key, secret and certificate management
- Backup, retention, deletion, legal hold and evidence integrity
- High availability, fault tolerance, RTO and RPO

**Exercise:** Map a dataset across create, store, use, share, archive and destroy phases with required controls.

### C5 Secure Architecture and IaC

**Objective:** Explain how repeatable architecture reduces recurring vulnerabilities.

**Topics:**

- Landing zones, account/project structure and guardrails
- Central logging, configuration baselines and asset inventory
- IaC review, policy-as-code, version control and change approval
- Secure defaults, deny guardrails and drift detection

**Exercise:** Review a Terraform or CloudFormation file and mark preventive, detective and evidence controls.

### C6 How Cloud Vulnerabilities Creep In

**Objective:** Trace vulnerability introduction from design through operation.

**Common causes:**

- Insecure default or copied template
- Broad temporary permission that becomes permanent
- Manual console change outside IaC
- Public exposure added for troubleshooting
- Long-lived secret copied into code or CI/CD
- New asset not added to inventory or monitoring
- Provider service evolves but the baseline does not
- Ownership and remediation deadlines are unclear

**Exercise:** Place sample vulnerabilities on the design, build, deploy, operate and retire lifecycle.

### C7 Identity, Exposure and Metadata Attack Paths

**Objective:** Connect individual vulnerabilities into realistic cloud attack paths.

**Patterns:**

- Public storage to artifact disclosure
- Open service to application weakness
- Application weakness to metadata/runtime identity
- Excess identity permission to sensitive data or control-plane change
- CI/CD token to deployment and cloud role
- Missing logs to delayed detection and weak evidence

**Exercise:** Build an attack graph and identify the earliest control that breaks the path.

### C8 Provider-Specific Patterns

**Objective:** Recognize equivalent controls across providers.

**Exercise:** Normalize AWS, GCP, Azure and DigitalOcean mini-cases into a common evidence record.

### C9 How CloudGuard Helps: Scanners and Jobs

**Capabilities:**

- AWS and CloudFox-assisted workflows
- GCP service-account/project scanning
- IaC file and repository scanning
- Web/application checks through Nuclei and OWASP ZAP paths
- Secret and dependency checks through Gitleaks, Trivy and Safety paths
- PostgreSQL-backed `scan_jobs` queue, scheduler, workers, retries, cancellation and dead-letter handling

**Exercise:** Start a scan job and follow its lifecycle from queued to evidence output.

### C10 How CloudGuard Helps: Evidence and GRC

**Capabilities:**

- Connectors normalize external scanner output
- Evidence includes tenant, source, scanner, job, asset, finding, severity, control and timestamp
- Raw artifact and normalized finding are stored separately
- Compliance dashboard shows framework coverage, evidence count, control status and remediation context
- Multi-tenant design requires `tenant_id` on every scanner-facing record and query

**Exercise:** Submit a connector payload and map the finding to control, owner, due date and closure proof.

### C11 Cloud Capstone

Teams receive an isolated tenant with IaC, IAM, storage, network, logging and CI/CD weaknesses. They must identify the highest-risk connected path, validate it using CloudGuard, ingest evidence, map controls, and deliver a five-minute briefing.

# Track B: Kubernetes Security - Separate Two Days

## Track Objectives

Participants will be able to:

- Explain container and Kubernetes architecture, objects, identities, networking, storage and scheduling.
- Recognize workload, RBAC, service exposure, network-policy, secret, image and supply-chain vulnerabilities.
- Connect Kubernetes vulnerabilities into cluster attack paths and blast-radius decisions.
- Scan a disposable cluster using kubeconfig and compare live state with IaC.
- Normalize Kubernetes evidence and map it into the CloudGuard compliance dashboard.

## Kubernetes Day 1: Foundations and Secure Design

| Time | Module | Focus | CISSP | CCSP |
|---|---|---|---|---|
| 09:00-09:30 | K0 Orientation and cluster lab | Scope, kubeconfig, namespaces and evidence flow | D1, D6 | D5, D6 |
| 09:30-10:45 | K1 Containers and Kubernetes basics | Images, containers, cluster purpose and orchestration | D3, D8 | D1, D3, D4 |
| 11:00-12:15 | K2 Cluster architecture and objects | Control plane, nodes, pods, controllers and services | D3, D4 | D1, D3 |
| 13:15-14:30 | K3 Identity, RBAC and tenancy | Service accounts, Roles, bindings and namespaces | D5 | D3, D5 |
| 14:45-15:45 | K4 Networking, storage and secrets | CNI, services, policies, volumes, ConfigMaps and Secrets | D2, D3, D4 | D2, D3 |
| 15:45-17:00 | K5 Secure delivery and observability | Images, registries, admission, IaC, logs and audit | D6, D7, D8 | D3, D4, D5 |

## Kubernetes Day 2: Vulnerabilities and How CloudGuard Helps

| Time | Module | Focus | CISSP | CCSP |
|---|---|---|---|---|
| 09:00-10:15 | K6 How Kubernetes vulnerabilities creep in | Weak YAML, drift, defaults, exceptions and ownership | D3, D6, D8 | D3, D4, D5 |
| 10:30-11:45 | K7 Workload and node-risk patterns | Privilege, host access, capabilities and unsafe runtime | D3, D7 | D3, D4, D5 |
| 12:45-13:45 | K8 RBAC, network and secret attack paths | Broad bindings, exposed services, missing policies and secret access | D2, D4, D5 | D2, D3, D5 |
| 13:45-15:00 | K9 Supply-chain and IaC drift | Images, dependencies, manifests, admission and live-state drift | D6, D8 | D3, D4, D5 |
| 15:15-16:00 | K10 CloudGuard Kubernetes scanner and GRC | Kubeconfig, live inventory, RBAC, network and evidence mapping | D6, D7 | D3, D5, D6 |
| 16:00-17:00 | K11 Kubernetes capstone | Scan, prioritize, remediate and prove closure | D1-D8 | D1-D6 |

## Kubernetes Module Details

### K0 Orientation and Cluster Lab

Confirm assigned kubeconfig/context, namespace, disposable cluster boundaries, scanner endpoint, evidence tenant and cleanup process.

### K1 Containers and Kubernetes Basics

**Topics:** image, container, runtime, registry, orchestration, desired state, declarative configuration and reconciliation.

**Exercise:** Trace an application from image build to registry, pod, service and external request.

### K2 Cluster Architecture and Objects

**Topics:** API server, etcd, scheduler, controller manager, kubelet, container runtime, Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs and Services.

**Exercise:** Match each object to its control-plane component, lifecycle and failure impact.

### K3 Identity, RBAC and Tenancy

**Topics:** users, groups, service accounts, tokens, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, namespace isolation and external identity integration.

**Exercise:** Calculate effective access for a prepared service account and reduce its permissions.

### K4 Networking, Storage and Secrets

**Topics:** cluster networking, CNI, DNS, ClusterIP, NodePort, LoadBalancer, ingress, NetworkPolicy, persistent volumes, storage classes, ConfigMaps and Secrets.

**Exercise:** Draw allowed traffic, identify missing policy boundaries, and classify mounted data.

### K5 Secure Delivery and Observability

**Topics:** image provenance, registry controls, vulnerability scanning, signing, admission control, policy-as-code, IaC, audit logs, events and runtime monitoring.

**Exercise:** Review a deployment pipeline and identify preventive, admission, runtime and evidence controls.

### K6 How Kubernetes Vulnerabilities Creep In

**Common causes:**

- Copied YAML with privileged or root settings
- Temporary exception to admission policy
- Broad service account or cluster binding
- Service changed to NodePort/LoadBalancer for troubleshooting
- Secret mounted into an unnecessary workload
- NetworkPolicy omitted for a new namespace
- Image tag floats to an unreviewed version
- Manual cluster change creates drift from Git/IaC
- Scanner warning has no owner or remediation deadline

### K7 Workload and Node-Risk Patterns

**Patterns:** privileged containers, hostPID/hostNetwork, hostPath, dangerous capabilities, root execution, writable root filesystem, missing limits and node-level access.

**Exercise:** Review prepared manifests and prioritize findings by escape potential and node blast radius.

### K8 RBAC, Network and Secret Attack Paths

**Patterns:** broad ClusterRoleBindings, token auto-mount, exposed services, missing east-west policy, namespace crossover and secret visibility.

**Exercise:** Build a path from exposed service to workload identity to secret or cluster action.

### K9 Supply-Chain and IaC Drift

**Patterns:** vulnerable base image, leaked registry credential, unsigned image, mutable tag, hardcoded secret, unsafe manifest and live-state drift.

**Exercise:** Compare repository manifests with live resources and create an evidence-backed drift finding.

### K10 How CloudGuard Helps Kubernetes

**Capabilities:**

- Validate kubeconfig and connect to the assigned live cluster
- Query pods, services, namespaces, deployments, jobs and cronjobs
- Review RoleBindings and ClusterRoleBindings
- Identify exposed services and missing NetworkPolicies
- Detect risky workload settings and secret exposure patterns
- Compare live resources with Kubernetes IaC manifests
- Enrich managed-cluster context when AWS/GCP credentials exist
- Store findings as tenant-scoped evidence and map them to controls

**Exercise:** Run the scanner, inspect job/evidence lineage, prioritize findings and verify one remediation through rescan.

### K11 Kubernetes Capstone

Teams receive a disposable cluster with intentional workload, RBAC, service, network-policy, secret, image and drift weaknesses. They must identify the highest-risk path, validate it through CloudGuard, map the evidence to controls and owners, remediate selected findings, and prove closure.

# Shared Assessment Model

| Area | Points |
|---|---:|
| Foundation and architecture understanding | 15 |
| Accurate vulnerability/root-cause analysis | 20 |
| Attack-path and blast-radius reasoning | 20 |
| Scanner validation and evidence quality | 20 |
| CISSP/CCSP control mapping | 10 |
| Remediation and closure proof | 10 |
| Executive communication | 5 |

# Official References

- ISC2 CISSP Exam Outline, effective 15 April 2024: `https://www.isc2.org/certifications/cissp/cissp-certification-exam-outline`
- ISC2 CCSP Exam Outline and announced 1 August 2026 update: `https://www.isc2.org/certifications/ccsp/ccsp-certification-exam-outline`
- DeepTrustxAI official logo: `https://deeptrustxai.com/images/darkmode.png`
