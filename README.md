# CloudGuard: Multi-Cloud Security Scanner

CloudGuard is an AI-powered Cloud Security Posture Management (CSPM) and vulnerability scanning platform designed for AWS and GCP environments. It identifies misconfigurations, exposed secrets, and security vulnerabilities using deep scanning and AI-driven remediation analysis.

## 🚀 Key Features
- **Multi-Cloud Support**: Comprehensive scanning for AWS and GCP resources.
- **Deep Scanning**: Crawls cloud endpoints to find exposed sensitive files (e.g., `.env`, `.git/config`).
- **IAM Analysis**: Detects complex privilege escalation paths in GCP and AWS IAM policies.
- **AI Remediation**: Provides specific, actionable CLI commands and code snippets to fix found vulnerabilities.
- **Vulnerability Orchestration**: Integrates industry-standard tools like Trivy, Nuclei, Gitleaks, Grype, and Safety into a single dashboard.

## 🛠️ Architecture
- **Backend**: Python (FastAPI) with an MCP (Model Context Protocol) server architecture.
- **Frontend**: Premium Vanilla JS/HTML/CSS dashboard with real-time updates.
- **Database**: PostgreSQL for scan history and credential management.
- **Infrastructure**: Containerized with Docker and orchestrated with Docker Compose.

## 📂 Project Structure
- `backend/`: Core logic, MCP plugins, and vulnerability integration.
- `frontend/`: Interactive security dashboard and credential management UI.
- `config/`: System and tool configurations.
- `db/`: Database initialization scripts and schemas.

## 🚦 Quick Start
1. **Environment Setup**: Create a `.env` file with your `DATABASE_URL` and `OPENAI_API_KEY`.
2. **Launch Services**:
   ```bash
   docker-compose --profile dev up
   ```
3. **Access Dashboard**: Open `http://localhost:3000` in your browser.

## 🔒 Security & Privacy
CloudGuard stores credentials in an encrypted PostgreSQL database. In development mode, encryption is bypassed for ease of use, but production deployments utilize full Fernet encryption for all sensitive fields.

---
*Created for secure, proactive cloud vulnerability management.*
