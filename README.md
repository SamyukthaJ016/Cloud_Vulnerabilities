# 🛡️ CloudGuard Security Scanner

**CloudGuard** is a high-performance, automated multi-cloud security scanner designed to identify vulnerabilities, misconfigurations, and over-privileged IAM identities across AWS and GCP environments. 

Built on a modern **Control Plane (MCP)** architecture, CloudGuard combines deep-scan capabilities with AI-powered recommendations to provide a unified security posture for cloud-native infrastructure.

---

## ✨ Key Features

### 🌐 Multi-Cloud Visibility
- **AWS Surface Analysis**: Scans S3 buckets, EC2 instances, IAM roles, and more.
- **GCP Insights**: Identifies public cloud assets and security gaps in Google Cloud projects.
- **Unified Dashboard**: View providers, assets, and findings in a sleek, interactive real-time interface.

### ⏰ Advanced Scheduling & Automation
- **Recurring Scans**: Configure scans to run every 10m, 30m, 1h, 6h, or at daily/weekly intervals.
- **Custom Timezones**: Schedule scans to align with your organization's business hours.
- **Continuous Monitoring**: Automatic re-runs ensure that new misconfigurations are caught within minutes.

### 🛡️ Smart Permission Auto-Fix
- **IAM "Access Denied" Handler**: If a scan fails due to missing permissions, CloudGuard generates the exact AWS CLI commands needed to fix the issue.
- **Auto-Retry Flow**: Grant permissions via the UI and automatically retry the scan without re-entering configuration.

### 🤖 AI Recommendations
- Powered by OpenAI to summarize raw scanning results.
- Provides actionable steps and risk assessment for every finding.

### 📧 Real-time Notifications
- **SMTP Alerts**: Receive HTML security summaries directly in your inbox as soon as a scan completes.
- **Customizable Delivery**: Choose which email addresses receive alerts for specific schedules.

---

## 🏗️ Architecture

CloudGuard uses a distributed architecture for scalability:
- **Backend**: Python (FastAPI) handles the API, scan logic, and AI integration.
- **Worker**: Standalone Scheduler Worker manages background task execution and email dispatch.
- **Database**: PostgreSQL for persistent storage of scan history, findings, and schedules.
- **Task Queue**: Redis-backed queue for reliable background processing.

---

## 🚀 Getting Started

### Prerequisites
- Docker & Docker Compose
- AWS/GCP Credentials
- OpenAI API Key (optional, for AI features)
- SMTP Server (e.g., Gmail App Password) for email alerts

### Setup & Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/CloudGuard.git
   cd CloudGuard
   ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in your details:
   ```bash
   DATABASE_URL=postgresql://scanner_user:scanner_pass@postgres:5432/scanner_db
   OPENAI_API_KEY=sk-your-key
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ```

3. **Launch with Docker Compose**:
   ```bash
   docker compose --profile dev up --build
   ```

4. **Access the UI**:
   Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## 📖 Usage Guide

### Running an Immediate Scan
1. Navigate to the **Scan** tab.
2. Enter your Cloud Provider details (Account IDs/Region).
3. Click "Scan Now". CloudGuard will initialize the MCP servers and stream results in real-time.

### Setting Up Recurring Scans
1. Navigate to the **Recurring Scan** tab.
2. Select your frequency (e.g., every 10 minutes) and enter your notification email.
3. Save the schedule. The worker will handle the rest!

## 🛠️ Security Toolchain

CloudGuard integrates several industry-standard security tools to provide comprehensive analysis. For the best experience, ensure these tools are installed on your system or within your scanning environment.

### 🦊 CloudFox
IAM and Cloud infrastructure analysis.
- **Install (Go)**: `go install github.com/BishopFox/cloudfox@latest`
- **Install (Homebrew)**: `brew install bishopfox/tap/cloudfox`
- **Install (Scoop)**: `scoop install cloudfox`
- **Documentation**: [github.com/BishopFox/cloudfox](https://github.com/BishopFox/cloudfox)

### 🛡️ Trivy
Vulnerability scanner for containers, filesystems, and Git repos.
- **Install (Homebrew)**: `brew install aquasecurity/tap/trivy`
- **Install (Linux)**: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
- **Install (Windows)**: `winget install aquasecurity.trivy` or `scoop install trivy`
- **Documentation**: [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/)

### 🔍 Nuclei
Fast and customizable vulnerability scanner.
- **Install (Homebrew)**: `brew install nuclei`
- **Install (Go)**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **Install (Windows)**: `winget install projectdiscovery.nuclei` or `scoop install nuclei`
- **Documentation**: [nuclei.projectdiscovery.io](https://nuclei.projectdiscovery.io/)

### 🔑 Gitleaks
Secret scanning for hardcoded credentials.
- **Install (Homebrew)**: `brew install gitleaks`
- **Install (Docker)**: `docker pull zricethezav/gitleaks`
- **Install (Windows)**: `winget install gitleaks` or `scoop install gitleaks`
- **Documentation**: [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)

### 🐍 Safety
Python dependency vulnerability scanner.
- **Install (Pip)**: `pip install safety`
- **Documentation**: [github.com/pyupio/safety](https://github.com/pyupio/safety)

### 📦 OWASP Dependency-Check
Multi-language software composition analysis.
- **Install (Homebrew)**: `brew install dependency-check`
- **Install (Windows)**: `winget install OWASP.DependencyCheck` or `scoop install dependency-check`
- **Documentation**: [owasp.org/www-project-dependency-check](https://owasp.org/www-project-dependency-check/)

### 🕸️ OWASP ZAP
Web application security scanner.
- **Install**: [Download ZAP](https://www.zaproxy.org/download/) or use `zap-cli`
- **Install (Windows)**: `winget install OWASP.ZAP` or `scoop install zap`
- **Documentation**: [zaproxy.org](https://www.zaproxy.org/)

---

## 🛠️ Technology Stack
- **Backend**: FastAPI, Psycopg2, Pydantic, OpenAI.
- **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism), Vanilla JavaScript.
- **Infrastructure**: Docker, Nginx, Redis, PostgreSQL.
- **Scanning Tools**: Integrated with CloudFox, Nuclei, and custom MCP Plugins.

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.
