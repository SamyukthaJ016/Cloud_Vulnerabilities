# Module Configuration

Learn how to enable or disable platform modules to customize GigaChad GRC for your organization's needs.

## Overview

GigaChad GRC is a modular platform. You can enable only the modules relevant to your compliance program, reducing interface complexity and focusing on what matters.

## Available Modules

| Module | Description |
|--------|-------------|
| **Compliance** | Controls, Frameworks, Evidence, Calendar |
| **Data** | Policies, Assets, Integrations |
| **Risk** | Risk Dashboard, Register, Heatmap, Scenarios |
| **TPRM** | Vendors, Assessments, Contracts, Questionnaires |
| **BC/DR** | Business Continuity, Disaster Recovery |
| **Audit** | Internal Audits, Findings, Requests |
| **Trust** | Trust Center, Knowledge Base |
| **People** | Employee Compliance, Training |
| **AI** | AI Features, MCP Servers |
| **Tools** | Custom Dashboards, Scheduled Reports |

## Common Configurations

### Core GRC Only

For compliance and risk management without vendor or BC/DR modules:
- ✅ Compliance, Data, Risk, Audit, Tools
- ❌ TPRM, BC/DR, Trust, People, AI

### Compliance Focused

For organizations only needing compliance tracking:
- ✅ Compliance, Data
- ❌ Risk, TPRM, BC/DR, Audit, Trust, People, AI, Tools

### Full Platform

All modules enabled for comprehensive GRC:
- ✅ All modules (except AI by default)

## How to Configure

There are two ways to configure modules:

### 1. In the UI (per organization)

For most admins, this is the recommended path:

1. Sign in as an **administrator** (admin or super_admin).
2. Navigate to **Settings → Module Configuration**.
3. Choose a preset (Full Platform, Core GRC, Compliance Only, etc.) or toggle modules individually.
4. Click **Save Configuration**.

This updates the modules for the current organization only. You can have different orgs with different
module sets in the same deployment.

### 2. Via environment variables (deployment defaults)

For platform operators setting global defaults:

1. Edit the frontend environment configuration (`.env` file) or deployment config.
2. Set `VITE_ENABLE_*_MODULE=true` or `false` for each module.
3. Rebuild and redeploy the frontend.

## What Happens When a Module is Disabled?

- **Navigation hidden** - Module menu items won't appear in the sidebar
- **Routes blocked** - Direct URL access shows a "Module Not Enabled" page
- **Data preserved** - Your data remains safe and available when re-enabled

## Need Help?

Contact your administrator to discuss which modules best fit your compliance program needs.

