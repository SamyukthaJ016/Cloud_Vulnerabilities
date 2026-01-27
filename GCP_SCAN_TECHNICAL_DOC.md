# Technical Documentation: GCP Security Scanning Engine

This document provides a detailed breakdown of the tools, libraries, and cloud resources utilized by the platform to perform security audits on Google Cloud Platform (GCP).

---

## 1. Core Scanning Technology Stack

The application uses a modular **MCP (Model Context Protocol)** architecture. This allows the backend to act as a "Security Server" that orchestrates various specialized scanning modules.

### A. Python Libraries (The Engine)
The following key Python packages are used to interact with GCP and process data:

| Package | Purpose |
| :--- | :--- |
| `google-cloud-storage` | Used to audit GCS bucket permissions, ACLs, and encryption settings. |
| `google-cloud-compute` | Interacts with the Compute Engine API to scan VM instances and Firewall rules. |
| `google-cloud-iam` | Audits Service Accounts and IAM Policies for over-privileged users. |
| `google-cloud-functions` | Inspects serverless functions for public access and secure triggers. |
| `google-cloud-resourcemanager` | Validates Project-level metadata and organization-wide security policies. |
| `google-auth` | Handles secure authentication using Service Account JSON keys. |
| `httpx / requests` | Used by the Web Scanner to probe public endpoints for OWASP vulnerabilities. |

---

## 2. Resources Scanned in GCP

The application performs a deep-dive into these specific GCP resources to find vulnerabilities:

### 🛡️ Identity & Access (IAM)
*   **IAM Policies:** Looking for `allUsers` or `allAuthenticatedUsers` permissions.
*   **Service Accounts:** Checking for long-lived keys and "Owner" role assignments.
*   **MFA Status:** Determining if administrative accounts lack Multi-Factor Authentication.

### 📦 Storage (GCS)
*   **Public Buckets:** Detecting if anyone on the internet can read or write to your data.
*   **Encryption:** Checking if data is encrypted at rest using Google-managed or Customer-managed keys (CMEK).
*   **Uniform Bucket-Level Access:** Ensuring consistent permission management across the bucket.

### 🌐 Networking (VPC)
*   **Firewall Rules:** Identifying "Ingress" rules that allow traffic from `0.0.0.0/0` on sensitive ports (22-SSH, 3389-RDP, 5432-DB).
*   **Network Exposure:** Mapping external IPs of Compute instances.

### 💻 Compute Engine
*   **Instance Security:** Auditing Shielded VM settings, Secure Boot, and Integrity Monitoring.
*   **IP Exposure:** Flagging VMs that have public IPv4 addresses unnecessarily.

### ⚡ Cloud Functions
*   **Trigger Security:** Checking if functions allow "Unauthenticated Invocation."
*   **IAM Bindings:** Ensuring only authorized service accounts can trigger serverless logic.

---

## 3. Integrated Security Tools

The application doesn't just check configurations; it integrates active security tools:

1.  **GCP Configuration Auditor (Proprietary Logic):**
    *   A custom-built engine in `backend/mcp_servers/gcp_server.py` that maps API responses against security best practices (CIS Benchmarks).
2.  **Web Vulnerability Scanner:**
    *   A custom implementation using `httpx` to check for **Information Leakage** (Exposed `.env`, `.git`, `config.json`).
    *   Probes for common **Web Exploits** (XSS, Open Redirects).
3.  **AI Analysis Engine (OpenAI Integration):**
    *   Uses **GPT-4o-mini** to analyze raw JSON data from GCP and translate it into human-readable remediation steps and `gcloud` commands.

---

## 4. Operational Flow
1.  **Auth:** `google-auth` validates the Service Account.
2.  **Discovery:** Parallel tasks fetch data from 5+ GCP APIs.
3.  **Audit:** Logic engine flags resources that deviate from the "Secure Baseline."
4.  **Logging:** Every tool's success/failure is logged to the `scan_metadata` using the **Execution Health System**.
5.  **Storage:** Results are archived in **PostgreSQL** for historical trend analysis.

---
**Document Status:** 📄 Official Technical Reference
**Project:** CloudGuard Multi-Cloud Security Dashboard
**Target Provider:** Google Cloud Platform (GCP)
