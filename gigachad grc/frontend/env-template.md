# Frontend Environment Configuration

Copy the environment variables below to a `.env.local` file for local development or `.env.production` for production builds.

## Configuration Template

```env
# ========================================
# GigaChad GRC Frontend Configuration
# ========================================

# ========================================
# Required Configuration
# ========================================

# Backend API URL
# Development: Leave empty (uses Vite proxy)
# Production: Full URL to your API (e.g., https://grc.yourcompany.com)
VITE_API_URL=

# ========================================
# Authentication (Keycloak)
# ========================================

# Keycloak server URL
# Development: http://localhost:8080
# Production: https://auth.yourcompany.com
VITE_KEYCLOAK_URL=http://localhost:8080

# Keycloak realm name
VITE_KEYCLOAK_REALM=gigachad-grc

# Keycloak client ID for frontend
VITE_KEYCLOAK_CLIENT_ID=grc-frontend

# ========================================
# Error Tracking (Sentry)
# ========================================

# Enable/disable error tracking
# Set to "true" to enable Sentry error reporting
VITE_ERROR_TRACKING_ENABLED=false

# Sentry DSN (Data Source Name)
# Get this from your Sentry project settings
# Example: https://xxx@sentry.io/123
VITE_SENTRY_DSN=

# Application version for error tracking
# Typically set during CI/CD build
VITE_APP_VERSION=

# Environment name for error tracking
# Defaults to NODE_ENV if not set
VITE_ENV=development

# ========================================
# Module Configuration
# ========================================
# Enable/disable platform modules based on your needs.
# Set to "true" to enable, "false" to disable.
# Disabled modules hide navigation and block access to routes.

# COMPLIANCE MODULE - Controls, Frameworks, Evidence, Calendar
# Core module for compliance management
VITE_ENABLE_COMPLIANCE_MODULE=true

# DATA MODULE - Policies, Assets, Integrations  
# Data governance and asset management
VITE_ENABLE_DATA_MODULE=true

# RISK MODULE - Risk Dashboard, Register, Heatmap, Scenarios
# Risk identification and assessment
VITE_ENABLE_RISK_MODULE=true

# TPRM MODULE - Vendors, Assessments, Contracts, Questionnaires
# Third-party risk management
VITE_ENABLE_TPRM_MODULE=true

# BCDR MODULE - BC/DR Dashboard, Business Processes, Plans, Tests, Runbooks
# Business Continuity and Disaster Recovery
VITE_ENABLE_BCDR_MODULE=true

# AUDIT MODULE - Audits, Findings, Requests, Audit Log
# Internal audit management
VITE_ENABLE_AUDIT_MODULE=true

# TRUST MODULE - Trust Center, Knowledge Base
# Customer-facing trust portal
VITE_ENABLE_TRUST_MODULE=true

# PEOPLE MODULE - Employee Compliance, Training, Awareness
# Employee compliance tracking
VITE_ENABLE_PEOPLE_MODULE=true

# AI MODULE - AI Features, MCP Server Integration
# AI-powered features (requires API keys)
VITE_ENABLE_AI_MODULE=false

# TOOLS MODULE - Custom Dashboards, Scheduled Reports
# Additional reporting and dashboard tools
VITE_ENABLE_TOOLS_MODULE=true

# ========================================
# Legacy Feature Flags (deprecated)
# ========================================
# These are kept for backwards compatibility.
# Use the module configuration above instead.

# Enable AI-powered features (use VITE_ENABLE_AI_MODULE instead)
VITE_ENABLE_AI_FEATURES=false

# Enable MCP servers (use VITE_ENABLE_AI_MODULE instead)
VITE_ENABLE_MCP_SERVERS=false

# Enable Trust Center (use VITE_ENABLE_TRUST_MODULE instead)
VITE_ENABLE_TRUST_CENTER=true

# Enable employee compliance (use VITE_ENABLE_PEOPLE_MODULE instead)
VITE_ENABLE_EMPLOYEE_COMPLIANCE=true

# Enable questionnaires (use VITE_ENABLE_TPRM_MODULE instead)
VITE_ENABLE_QUESTIONNAIRES=true

# ========================================
# Development Options
# ========================================

# Enable development authentication bypass
# WARNING: Never enable in production!
VITE_ENABLE_DEV_AUTH=false

# Log level for frontend
# Options: debug, info, warn, error
VITE_LOG_LEVEL=info
```

## Module Configuration Presets

Choose a preset that matches your needs. See [MODULE_CONFIGURATION.md](../docs/MODULE_CONFIGURATION.md) for detailed guidance.

### Preset: Full Platform (All Modules)

```env
VITE_ENABLE_COMPLIANCE_MODULE=true
VITE_ENABLE_DATA_MODULE=true
VITE_ENABLE_RISK_MODULE=true
VITE_ENABLE_TPRM_MODULE=true
VITE_ENABLE_BCDR_MODULE=true
VITE_ENABLE_AUDIT_MODULE=true
VITE_ENABLE_TRUST_MODULE=true
VITE_ENABLE_PEOPLE_MODULE=true
VITE_ENABLE_AI_MODULE=false
VITE_ENABLE_TOOLS_MODULE=true
```

### Preset: Core GRC Only

For organizations focused on compliance and risk management:

```env
VITE_ENABLE_COMPLIANCE_MODULE=true
VITE_ENABLE_DATA_MODULE=true
VITE_ENABLE_RISK_MODULE=true
VITE_ENABLE_TPRM_MODULE=false
VITE_ENABLE_BCDR_MODULE=false
VITE_ENABLE_AUDIT_MODULE=true
VITE_ENABLE_TRUST_MODULE=false
VITE_ENABLE_PEOPLE_MODULE=false
VITE_ENABLE_AI_MODULE=false
VITE_ENABLE_TOOLS_MODULE=true
```

### Preset: Compliance Only

For organizations needing only compliance tracking:

```env
VITE_ENABLE_COMPLIANCE_MODULE=true
VITE_ENABLE_DATA_MODULE=true
VITE_ENABLE_RISK_MODULE=false
VITE_ENABLE_TPRM_MODULE=false
VITE_ENABLE_BCDR_MODULE=false
VITE_ENABLE_AUDIT_MODULE=false
VITE_ENABLE_TRUST_MODULE=false
VITE_ENABLE_PEOPLE_MODULE=false
VITE_ENABLE_AI_MODULE=false
VITE_ENABLE_TOOLS_MODULE=false
```

## Production Example (Full Platform)

```env
VITE_API_URL=https://grc.yourcompany.com
VITE_KEYCLOAK_URL=https://auth.yourcompany.com
VITE_KEYCLOAK_REALM=gigachad-grc
VITE_KEYCLOAK_CLIENT_ID=grc-frontend
VITE_ERROR_TRACKING_ENABLED=true
VITE_SENTRY_DSN=https://your-dsn@sentry.io/project
VITE_APP_VERSION=1.0.0
VITE_ENV=production
VITE_ENABLE_DEV_AUTH=false
VITE_LOG_LEVEL=warn

# Module Configuration
VITE_ENABLE_COMPLIANCE_MODULE=true
VITE_ENABLE_DATA_MODULE=true
VITE_ENABLE_RISK_MODULE=true
VITE_ENABLE_TPRM_MODULE=true
VITE_ENABLE_BCDR_MODULE=true
VITE_ENABLE_AUDIT_MODULE=true
VITE_ENABLE_TRUST_MODULE=true
VITE_ENABLE_PEOPLE_MODULE=true
VITE_ENABLE_AI_MODULE=false
VITE_ENABLE_TOOLS_MODULE=true
```

