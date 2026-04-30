# GigaChad GRC - API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Common Patterns](#common-patterns)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [API Endpoints](#api-endpoints)
   - [Controls Service](#controls-service)
   - [Frameworks Service](#frameworks-service)
   - [Policies Service](#policies-service)
   - [TPRM Service](#tprm-service)
   - [Trust Service](#trust-service)
   - [Audit Service](#audit-service)
   - [AI Service](#ai-service)
   - [MCP Service](#mcp-service)
7. [Health Endpoints](#health-endpoints)
8. [Webhooks](#webhooks)

---

## Overview

### Base URL

| Environment | Base URL |
|-------------|----------|
| Development | `http://localhost:80/api` |
| Staging | `https://staging.grc.example.com/api` |
| Production | `https://grc.example.com/api` |

### API Versioning

Currently, the API is unversioned. Future versions will use URL path versioning:

```
/api/v1/controls
/api/v2/controls
```

### Content Types

| Type | Media Type |
|------|------------|
| JSON | `application/json` |
| Form Data | `multipart/form-data` |
| Binary | `application/octet-stream` |

---

## Authentication

### OAuth 2.0 / OpenID Connect

GigaChad GRC uses Keycloak for authentication. All API requests must include a valid JWT token.

#### Request Headers

```http
Authorization: Bearer <access_token>
x-user-id: <user-uuid>
x-organization-id: <organization-uuid>
Content-Type: application/json
```

#### Obtaining Tokens

**Authorization Code Flow** (recommended for web apps):

```bash
# 1. Redirect user to Keycloak
https://auth.grc.example.com/auth/realms/grc/protocol/openid-connect/auth?
  response_type=code&
  client_id=grc-frontend&
  redirect_uri=https://grc.example.com/callback&
  scope=openid profile email

# 2. Exchange code for tokens
POST https://auth.grc.example.com/auth/realms/grc/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization_code>&
client_id=grc-frontend&
redirect_uri=https://grc.example.com/callback
```

**Client Credentials Flow** (for service-to-service):

```bash
POST https://auth.grc.example.com/auth/realms/grc/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=<service-client-id>&
client_secret=<service-client-secret>&
scope=openid
```

#### Token Refresh

```bash
POST https://auth.grc.example.com/auth/realms/grc/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=<refresh_token>&
client_id=grc-frontend
```

---

## Common Patterns

### Pagination

All list endpoints support pagination:

```http
GET /api/controls?page=1&limit=25&offset=0
```

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `page` | number | 1 | - | Page number (1-indexed) |
| `limit` | number | 25 | 100 | Items per page |
| `offset` | number | 0 | - | Items to skip |

**Response Format**:

```json
{
  "data": [...],
  "meta": {
    "total": 150,
    "page": 1,
    "limit": 25,
    "totalPages": 6,
    "hasMore": true
  }
}
```

### Filtering

```http
GET /api/controls?status=implemented&category=access_control&search=password
```

### Sorting

```http
GET /api/controls?sortBy=title&sortOrder=asc
```

| Parameter | Values | Default |
|-----------|--------|---------|
| `sortBy` | Field name | `createdAt` |
| `sortOrder` | `asc`, `desc` | `desc` |

### Field Selection

```http
GET /api/controls?fields=id,title,status,category
```

### Expansion

```http
GET /api/controls/123?expand=implementations,evidence
```

---

## Error Handling

### Error Response Format

```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "details": [
    {
      "field": "title",
      "message": "Title is required"
    }
  ],
  "timestamp": "2024-01-15T10:30:00.000Z",
  "path": "/api/controls"
}
```

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful GET, PUT, PATCH |
| 201 | Created | Successful POST |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Invalid input, validation error |
| 401 | Unauthorized | Missing or invalid token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Duplicate resource, constraint violation |
| 422 | Unprocessable Entity | Business logic error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Prisma Error Codes

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| P2002 | 409 | Unique constraint violation |
| P2003 | 400 | Foreign key constraint failed |
| P2025 | 404 | Record not found |

---

## Rate Limiting

### Default Limits

| Context | Limit | Window |
|---------|-------|--------|
| Per User | 100 requests | 1 minute |
| Per IP (unauthenticated) | 20 requests | 1 minute |
| Bulk operations | 10 requests | 1 minute |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312200000
```

### Rate Limit Exceeded Response

```json
{
  "statusCode": 429,
  "message": "Too Many Requests",
  "retryAfter": 45
}
```

---

## API Endpoints

## Controls Service

Base path: `/api/controls`

### Controls

#### List Controls

```http
GET /api/controls
```

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search in title, description, controlId |
| `status` | string | Filter by status |
| `category` | string | Filter by category |
| `framework` | string | Filter by framework mapping |
| `page` | number | Page number |
| `limit` | number | Items per page |

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "controlId": "AC-001",
      "title": "Access Control Policy",
      "description": "...",
      "category": "access_control",
      "status": "implemented",
      "owner": "John Doe",
      "frameworkMappings": ["SOC 2 CC6.1", "ISO 27001 A.9.1"],
      "evidenceCount": 5,
      "lastReviewDate": "2024-01-01T00:00:00Z",
      "nextReviewDate": "2025-01-01T00:00:00Z",
      "createdAt": "2023-01-01T00:00:00Z",
      "updatedAt": "2024-01-01T00:00:00Z"
    }
  ],
  "meta": {
    "total": 150,
    "page": 1,
    "limit": 25
  }
}
```

#### Get Control

```http
GET /api/controls/:id
```

**Response**: `200 OK`

#### Create Control

```http
POST /api/controls
Content-Type: application/json

{
  "controlId": "AC-001",
  "title": "Access Control Policy",
  "description": "Define and enforce access control policies",
  "category": "access_control",
  "status": "not_started",
  "owner": "John Doe",
  "frameworkMappings": ["SOC 2 CC6.1"],
  "tags": ["critical", "security"],
  "testingFrequency": "quarterly",
  "nextReviewDate": "2025-01-01"
}
```

**Response**: `201 Created`

#### Update Control

```http
PUT /api/controls/:id
Content-Type: application/json

{
  "status": "implemented",
  "lastReviewDate": "2024-01-15"
}
```

**Response**: `200 OK`

#### Delete Control (Soft Delete)

```http
DELETE /api/controls/:id
```

**Response**: `204 No Content`

#### Bulk Upload Controls

```http
POST /api/controls/bulk
Content-Type: application/json

{
  "controls": [...],
  "skipExisting": false,
  "updateExisting": true
}
```

### Evidence

#### List Evidence

```http
GET /api/evidence
```

#### Upload Evidence

```http
POST /api/evidence
Content-Type: multipart/form-data

file: <binary>
title: "AWS IAM Policy"
type: "document"
controlIds: ["uuid1", "uuid2"]
expiresAt: "2025-01-01"
```

**Response**: `201 Created`

```json
{
  "id": "uuid",
  "title": "AWS IAM Policy",
  "filename": "iam-policy.pdf",
  "size": 102400,
  "mimeType": "application/pdf",
  "url": "https://storage.../evidence/uuid/iam-policy.pdf",
  "expiresAt": "2025-01-01T00:00:00Z"
}
```

#### Download Evidence

```http
GET /api/evidence/:id/download
```

**Response**: `200 OK` with file binary

### Assets

#### List Assets

```http
GET /api/assets
```

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search name |
| `type` | string | Filter by type |
| `criticality` | string | Filter by criticality |
| `department` | string | Filter by department |

#### Create Asset

```http
POST /api/assets
Content-Type: application/json

{
  "name": "Production Database",
  "type": "database",
  "category": "data",
  "criticality": "critical",
  "owner": "DBA Team",
  "department": "Engineering",
  "metadata": {
    "engine": "PostgreSQL",
    "version": "16"
  }
}
```

---

## Frameworks Service

Base path: `/api/frameworks`

### Frameworks

#### List Frameworks

```http
GET /api/frameworks
```

#### Get Framework with Readiness

```http
GET /api/frameworks/:id
```

**Response**:

```json
{
  "id": "uuid",
  "name": "SOC 2 Type II",
  "version": "2024",
  "description": "...",
  "controls": 89,
  "readiness": {
    "score": 78,
    "implemented": 69,
    "inProgress": 12,
    "notStarted": 8
  }
}
```

### Risks

Base path: `/api/risks`

#### List Risks

```http
GET /api/risks
```

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status |
| `category` | string | Filter by category |
| `riskLevel` | string | Filter by risk level |
| `ownerId` | string | Filter by owner |

#### Create Risk

```http
POST /api/risks
Content-Type: application/json

{
  "title": "Data Breach Risk",
  "description": "Risk of unauthorized data access",
  "category": "security",
  "likelihood": "possible",
  "impact": "major",
  "status": "open",
  "ownerId": "uuid"
}
```

#### Risk Scenarios

```http
POST /api/risks/:id/scenarios
Content-Type: application/json

{
  "name": "SQL Injection Attack",
  "threatActor": "external_attacker",
  "attackVector": "web_application",
  "targetAssets": ["uuid1", "uuid2"],
  "likelihood": "likely",
  "impact": "critical"
}
```

#### Risk Workflow Actions

```http
# Validate risk intake
POST /api/risks/:id/validate
{
  "approved": true,
  "riskAssessorId": "uuid"
}

# Submit assessment
POST /api/risks/:id/assessment/submit
{
  "likelihoodScore": "likely",
  "likelihoodRationale": "...",
  "impactScore": "major",
  "impactRationale": "...",
  "recommendedOwnerId": "uuid"
}

# Treatment decision
POST /api/risks/:id/treatment/decision
{
  "decision": "mitigate",
  "justification": "...",
  "mitigationDescription": "...",
  "mitigationTargetDate": "2024-06-01"
}
```

### Risk Configuration

```http
GET /api/risk-config
PUT /api/risk-config
```

---

## Policies Service

Base path: `/api/policies`

### Policies

#### List Policies

```http
GET /api/policies
```

#### Upload Policy

```http
POST /api/policies
Content-Type: multipart/form-data

file: <binary>
title: "Information Security Policy"
version: "1.0"
status: "draft"
ownerId: "uuid"
reviewDate: "2025-01-01"
```

#### Policy Workflow

```http
# Submit for review
POST /api/policies/:id/submit

# Approve policy
POST /api/policies/:id/approve

# Publish policy
POST /api/policies/:id/publish

# Request acknowledgment
POST /api/policies/:id/request-acknowledgment
{
  "userIds": ["uuid1", "uuid2"]
}
```

#### Policy Statistics

```http
GET /api/policies/stats
```

**Response**:

```json
{
  "total": 25,
  "draft": 3,
  "inReview": 5,
  "approved": 2,
  "published": 15,
  "overdueReview": 2
}
```

---

## TPRM Service

Base path: `/api/vendors`, `/api/assessments`, `/api/contracts`, `/api/tprm-config`

### Vendors

#### List Vendors

```http
GET /api/vendors
```

#### Create Vendor

```http
POST /api/vendors
Content-Type: application/json

{
  "name": "AWS",
  "description": "Cloud infrastructure provider",
  "tier": "tier_1",
  "status": "active",
  "primaryContact": {
    "name": "John Doe",
    "email": "john@aws.com"
  },
  "riskRating": "low"
}
```

Note: When creating a vendor, the `reviewFrequency` and `nextReviewDue` are automatically calculated based on the tier configuration.

#### Get Reviews Due

Get vendors with upcoming or overdue reviews.

```http
GET /api/vendors/reviews-due?days=30
```

Response:
```json
{
  "upcoming": [
    {
      "id": "uuid",
      "name": "Vendor Name",
      "tier": "tier_1",
      "nextReviewDue": "2024-02-15",
      "daysUntilDue": 5
    }
  ],
  "overdue": [...]
}
```

#### Complete Review

Mark a vendor review as complete.

```http
POST /api/vendors/:vendorId/complete-review
```

#### Analyze Document with AI

Upload and analyze a SOC 2 or security document.

```http
POST /api/vendors/:vendorId/analyze-document
Content-Type: multipart/form-data

file: [binary document]
documentType: "soc2_type2"
```

Response:
```json
{
  "summary": "SOC 2 Type II report analysis...",
  "findings": {
    "exceptions": [
      {
        "control": "CC6.1",
        "description": "...",
        "severity": "medium"
      }
    ],
    "cuecs": [...],
    "gaps": [...]
  },
  "suggestedRiskScore": 35,
  "confidence": 0.82
}
```

#### Get Document Analysis

Retrieve previous document analysis results.

```http
GET /api/vendors/:vendorId/document-analysis/:analysisId
```

#### Create Assessment from Analysis

Generate a vendor assessment from AI analysis.

```http
POST /api/vendors/:vendorId/assessment-from-analysis
Content-Type: application/json

{
  "analysisId": "uuid",
  "createFindings": true
}
```

### Assessments

#### Create Assessment

```http
POST /api/assessments
Content-Type: application/json

{
  "vendorId": "uuid",
  "type": "security_questionnaire",
  "dueDate": "2024-03-01",
  "questions": [...]
}
```

#### Get Assessment Stats

Get assessment statistics.

```http
GET /api/assessments/stats
```

#### Get Upcoming Assessments

```http
GET /api/assessments/upcoming?days=30
```

#### Get Overdue Assessments

```http
GET /api/assessments/overdue
```

### Contracts

#### List Contracts

```http
GET /api/contracts
```

#### Create Contract

```http
POST /api/contracts
Content-Type: application/json

{
  "vendorId": "uuid",
  "title": "Cloud Services Agreement",
  "startDate": "2024-01-01",
  "endDate": "2025-01-01",
  "value": 120000,
  "autoRenew": true,
  "terms": "..."
}
```

### TPRM Configuration

#### Get Configuration

```http
GET /api/tprm-config
```

Response:
```json
{
  "id": "uuid",
  "organizationId": "default-org",
  "tierFrequencyMapping": {
    "tier_1": "monthly",
    "tier_2": "quarterly",
    "tier_3": "annual",
    "tier_4": "bi_annual"
  },
  "vendorCategories": [...],
  "riskThresholds": {...},
  "assessmentSettings": {...},
  "contractSettings": {...}
}
```

#### Update Configuration

```http
PUT /api/tprm-config
Content-Type: application/json

{
  "tierFrequencyMapping": {
    "tier_1": "custom_2",
    "tier_2": "quarterly"
  }
}
```

Note: Custom frequencies use `custom_X` format where X is months (e.g., `custom_2` = every 2 months).

#### Reset to Defaults

```http
POST /api/tprm-config/reset
```

#### Add Vendor Category

```http
POST /api/tprm-config/categories
Content-Type: application/json

{
  "id": "fintech",
  "name": "Financial Technology",
  "description": "Financial service providers",
  "defaultTier": "tier_2"
}
```

#### Remove Vendor Category

```http
DELETE /api/tprm-config/categories/:categoryId
```

#### Get Reference Data

Returns available options for configuration.

```http
GET /api/tprm-config/reference
```

---

## Trust Service

Base path: `/api/questionnaires`, `/api/knowledge-base`, `/api/trust-center`, `/api/answer-templates`, `/api/trust-config`, `/api/trust-ai`

### Questionnaires

#### List Questionnaires

```http
GET /api/questionnaires
```

#### Create Questionnaire

```http
POST /api/questionnaires
Content-Type: application/json

{
  "title": "SOC 2 Security Questionnaire",
  "sender": "Acme Corp",
  "dueDate": "2024-02-15",
  "priority": "high",
  "questions": [
    {
      "question": "Do you have an information security policy?",
      "category": "security",
      "required": true
    }
  ]
}
```

#### Get Dashboard Queue

Returns questions assigned to the user, overdue items, and items due this week.

```http
GET /api/questionnaires/dashboard-queue
```

#### Get Analytics

Returns questionnaire statistics and trends.

```http
GET /api/questionnaires/analytics
```

#### Find Similar Questions

Find previously answered questions similar to a given question.

```http
GET /api/questionnaires/questions/:questionId/similar
```

#### Find Duplicates in Questionnaire

Detect duplicate questions within a questionnaire.

```http
GET /api/questionnaires/:questionnaireId/duplicates
```

#### Export Questionnaire

Export questionnaire to various formats.

```http
GET /api/questionnaires/:questionnaireId/export?format=excel
```

Query params:
- `format`: `excel`, `csv`, `json`, `pdf`

### Knowledge Base

#### List Entries

```http
GET /api/knowledge-base
```

#### Create Entry

```http
POST /api/knowledge-base
Content-Type: application/json

{
  "question": "Are you SOC 2 certified?",
  "answer": "Yes, we maintain SOC 2 Type II certification...",
  "category": "compliance",
  "tags": ["soc2", "certification"]
}
```

#### Search Knowledge Base

Search for relevant KB entries.

```http
GET /api/knowledge-base/search?query=encryption
```

### Answer Templates

#### List Templates

```http
GET /api/answer-templates
```

#### Create Template

```http
POST /api/answer-templates
Content-Type: application/json

{
  "title": "SOC 2 Compliance Response",
  "content": "Our organization maintains SOC 2 Type II certification...",
  "category": "Compliance",
  "tags": ["soc2", "compliance", "audit"],
  "variables": ["certification_date"]
}
```

#### Get Template

```http
GET /api/answer-templates/:id
```

#### Update Template

```http
PUT /api/answer-templates/:id
Content-Type: application/json

{
  "title": "Updated SOC 2 Response",
  "content": "Updated content..."
}
```

#### Delete Template

```http
DELETE /api/answer-templates/:id
```

#### Archive/Unarchive Template

```http
POST /api/answer-templates/:id/archive
POST /api/answer-templates/:id/unarchive
```

#### Apply Template to Question

```http
POST /api/answer-templates/:id/apply
Content-Type: application/json

{
  "questionId": "uuid",
  "variables": {
    "certification_date": "2024-01-15"
  }
}
```

#### Get Template Stats

```http
GET /api/answer-templates/stats
```

#### Get Template Categories

```http
GET /api/answer-templates/categories
```

### Trust Configuration

#### Get Configuration

```http
GET /api/trust-config
```

Response:
```json
{
  "id": "uuid",
  "organizationId": "default-org",
  "slaSettings": {
    "urgentHours": 24,
    "highHours": 72,
    "normalHours": 120,
    "lowHours": 240,
    "businessHoursOnly": true
  },
  "assignmentSettings": {...},
  "kbSettings": {...},
  "trustCenterSettings": {...},
  "aiSettings": {...}
}
```

#### Update Configuration

```http
PUT /api/trust-config
Content-Type: application/json

{
  "slaSettings": {
    "urgentHours": 12,
    "highHours": 48
  }
}
```

#### Reset to Defaults

```http
POST /api/trust-config/reset
```

#### Get Reference Data

Returns available options for configuration fields.

```http
GET /api/trust-config/reference
```

### Trust AI

#### Draft Answer

Generate an AI-drafted answer for a question.

```http
POST /api/trust-ai/draft
Content-Type: application/json

{
  "questionId": "uuid",
  "questionText": "Do you encrypt data at rest?",
  "context": "optional additional context"
}
```

Response:
```json
{
  "draftedAnswer": "Yes, we implement AES-256 encryption for all data at rest...",
  "confidence": 0.85,
  "sources": [
    {
      "type": "knowledge_base",
      "id": "uuid",
      "title": "Encryption Policy",
      "relevance": 0.92
    }
  ]
}
```

#### Categorize Question

Automatically categorize a question.

```http
POST /api/trust-ai/categorize
Content-Type: application/json

{
  "questionText": "What is your incident response process?"
}
```

Response:
```json
{
  "category": "Incident Response",
  "confidence": 0.78,
  "alternativeCategories": [
    {"category": "Security Operations", "confidence": 0.45}
  ]
}
```

#### Improve Answer

Get AI suggestions to improve an existing answer.

```http
POST /api/trust-ai/improve
Content-Type: application/json

{
  "questionText": "Do you have a security policy?",
  "currentAnswer": "Yes",
  "improvementType": "expand"
}
```

Response:
```json
{
  "improvedAnswer": "Yes, we maintain a comprehensive information security policy...",
  "improvements": [
    "Added specific policy details",
    "Mentioned review frequency",
    "Referenced compliance standards"
  ]
}
```

### Trust Center

#### Get Public Trust Center

```http
GET /api/trust-center/public/:organizationId
```

#### Get Configuration

```http
GET /api/trust-center/config
```

---

## Audit Service

Base path: `/api/audits`, `/api/audit-requests`, `/api/audit-findings`, `/api/audit-portal`

### Audits

#### List Audits

```http
GET /api/audits
```

#### Create Audit

```http
POST /api/audits
Content-Type: application/json

{
  "name": "SOC 2 Type II Annual Audit",
  "type": "external",
  "framework": "SOC 2",
  "auditorFirm": "Big Four LLP",
  "startDate": "2024-02-01",
  "endDate": "2024-04-01"
}
```

### Audit Requests

#### Create Evidence Request

```http
POST /api/audit-requests
Content-Type: application/json

{
  "auditId": "uuid",
  "title": "Access Control Policies",
  "description": "Please provide all access control policies",
  "dueDate": "2024-02-15",
  "assigneeId": "uuid",
  "priority": "high"
}
```

### Audit Portal

#### Portal Access (for external auditors)

```http
GET /api/audit-portal/:auditId
Authorization: Bearer <portal-access-token>
```

### Audit AI

AI-powered features for audit automation and intelligence.

#### Categorize Finding

Automatically categorize an audit finding based on its description.

```http
POST /api/audit/ai/categorize-finding
Content-Type: application/json

{
  "findingId": "uuid",
  "description": "User access reviews are not performed on a quarterly basis..."
}
```

**Response**: `200 OK`

```json
{
  "category": "Access Control",
  "subcategory": "User Access Review",
  "confidence": 0.92,
  "suggestedTags": ["access-management", "periodic-review", "uar"]
}
```

#### Analyze Evidence Gaps

Identify gaps in evidence coverage for an audit scope.

```http
POST /api/audit/ai/analyze-gaps
Content-Type: application/json

{
  "auditId": "uuid",
  "scope": "SOC 2 Type II - Security and Availability"
}
```

**Response**: `200 OK`

```json
{
  "gaps": [
    {
      "controlArea": "CC6.1 - Logical Access",
      "missingEvidence": ["User access provisioning process documentation", "Access removal evidence"],
      "priority": "high",
      "recommendation": "Request access provisioning workflow documentation and recent termination samples"
    }
  ],
  "coveragePercentage": 78,
  "criticalGaps": 3
}
```

#### Suggest Remediation

Get AI-generated remediation recommendations for a finding.

```http
POST /api/audit/ai/suggest-remediation
Content-Type: application/json

{
  "findingId": "uuid",
  "description": "Firewall rules are not reviewed on a periodic basis"
}
```

**Response**: `200 OK`

```json
{
  "shortTermActions": [
    "Conduct an immediate review of all firewall rules",
    "Document the current rule set with business justifications"
  ],
  "longTermActions": [
    "Implement quarterly firewall rule review process",
    "Deploy automated rule analysis tool"
  ],
  "estimatedEffort": "40 hours",
  "suggestedOwner": "Network Security Team",
  "priority": "high"
}
```

#### Map Controls

Map an audit request or finding to relevant controls.

```http
POST /api/audit/ai/map-controls
Content-Type: application/json

{
  "requestId": "uuid",
  "description": "Evidence of password complexity requirements"
}
```

**Response**: `200 OK`

```json
{
  "mappedControls": [
    {
      "controlId": "CC6.1-03",
      "controlName": "Password Management",
      "confidence": 0.95,
      "framework": "SOC 2"
    },
    {
      "controlId": "A.9.4.3",
      "controlName": "Password Management System",
      "confidence": 0.88,
      "framework": "ISO 27001"
    }
  ]
}
```

### Audit Templates

Reusable audit program templates with checklists and pre-defined procedures.

#### List Audit Templates

```http
GET /api/audit/templates?auditType=soc2&status=active
```

**Query Parameters**:
- `auditType`: Filter by audit type (soc2, iso27001, hipaa, pci-dss, custom)
- `framework`: Filter by framework
- `status`: Filter by status (active, archived)
- `page`, `limit`: Pagination

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "SOC 2 Type II Audit Template",
      "description": "Comprehensive SOC 2 Type II audit program",
      "auditType": "soc2",
      "framework": "SOC 2",
      "isSystem": true,
      "status": "active",
      "checklistItems": [...],
      "requestTemplates": [...],
      "testProcedureTemplates": [...]
    }
  ],
  "total": 5,
  "page": 1,
  "limit": 20
}
```

#### Get Audit Template

```http
GET /api/audit/templates/:id
```

#### Create Audit Template

```http
POST /api/audit/templates
Content-Type: application/json

{
  "name": "Custom SOC 2 Template",
  "description": "Tailored SOC 2 audit program",
  "auditType": "soc2",
  "framework": "SOC 2",
  "checklistItems": [
    {
      "id": "item-1",
      "title": "Obtain prior audit report",
      "category": "planning",
      "required": true
    }
  ],
  "requestTemplates": [
    {
      "title": "Access Control Policy",
      "description": "Current access control policy document",
      "category": "policies"
    }
  ],
  "testProcedureTemplates": [
    {
      "title": "User Access Review Testing",
      "description": "Verify quarterly user access reviews are performed",
      "testType": "inspection",
      "sampleSize": 25
    }
  ]
}
```

#### Update Audit Template

```http
PUT /api/audit/templates/:id
Content-Type: application/json
```

#### Delete Audit Template

```http
DELETE /api/audit/templates/:id
```

#### Clone Template to New Audit

Create a new audit from a template.

```http
POST /api/audit/templates/:id/clone
Content-Type: application/json

{
  "auditName": "Q4 2024 SOC 2 Type II Audit"
}
```

**Response**: `201 Created`

```json
{
  "auditId": "uuid",
  "name": "Q4 2024 SOC 2 Type II Audit",
  "status": "planning",
  "checklistItemsCreated": 45,
  "requestsCreated": 32,
  "testProceduresCreated": 28
}
```

### Audit Workpapers

Version-controlled workpapers with review/approval workflow.

#### List Workpapers for Audit

```http
GET /api/audits/:auditId/workpapers?status=pending_review
```

**Query Parameters**:
- `status`: Filter by status (draft, pending_review, reviewed, approved, rejected)
- `preparedBy`: Filter by preparer user ID
- `page`, `limit`: Pagination

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "workpaperNumber": "WP-001",
      "title": "Control Testing - Access Management",
      "status": "pending_review",
      "version": 2,
      "preparedBy": "user-uuid",
      "preparedAt": "2024-12-10T10:00:00Z",
      "reviewedBy": null,
      "reviewedAt": null,
      "approvedBy": null,
      "approvedAt": null
    }
  ],
  "total": 15
}
```

#### Get Workpaper

```http
GET /api/audits/:auditId/workpapers/:id
```

**Response**: `200 OK`

```json
{
  "id": "uuid",
  "workpaperNumber": "WP-001",
  "title": "Control Testing - Access Management",
  "content": "## Objective\n\nTest the design and operating effectiveness...",
  "status": "pending_review",
  "version": 2,
  "attachments": [
    {
      "id": "att-uuid",
      "name": "evidence_screenshot.png",
      "type": "image/png"
    }
  ],
  "versionHistory": [
    {
      "version": 1,
      "changedAt": "2024-12-09T14:00:00Z",
      "changedBy": "user-uuid",
      "summary": "Initial draft"
    }
  ]
}
```

#### Create Workpaper

```http
POST /api/audits/:auditId/workpapers
Content-Type: application/json

{
  "workpaperNumber": "WP-002",
  "title": "Risk Assessment Documentation",
  "content": "## Scope\n\nThis workpaper documents..."
}
```

#### Update Workpaper

```http
PUT /api/audits/:auditId/workpapers/:id
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content..."
}
```

Note: Updates create a new version automatically.

#### Sign Off Workpaper

```http
POST /api/audits/:auditId/workpapers/:id/sign-off
Content-Type: application/json

{
  "role": "prepared" | "reviewed" | "approved"
}
```

**Response**: `200 OK`

```json
{
  "id": "uuid",
  "status": "reviewed",
  "reviewedBy": "user-uuid",
  "reviewedAt": "2024-12-11T09:30:00Z"
}
```

#### Delete Workpaper

```http
DELETE /api/audits/:auditId/workpapers/:id
```

### Remediation Plans (POA&M)

Plan of Action and Milestones management for audit findings.

#### List Remediation Plans

```http
GET /api/audit/remediation-plans?status=open&auditId=uuid
```

**Query Parameters**:
- `status`: Filter by status (open, in_progress, completed, overdue)
- `ownerId`: Filter by owner user ID
- `auditId`: Filter by audit
- `page`, `limit`: Pagination

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "planNumber": "POA-2024-001",
      "findingId": "finding-uuid",
      "description": "Implement quarterly access reviews",
      "status": "in_progress",
      "scheduledEnd": "2025-02-28",
      "milestones": [
        {
          "id": "m1",
          "title": "Define access review process",
          "dueDate": "2025-01-15",
          "status": "completed"
        },
        {
          "id": "m2",
          "title": "Implement tooling",
          "dueDate": "2025-02-01",
          "status": "in_progress"
        }
      ],
      "progressPercentage": 40
    }
  ],
  "total": 8
}
```

#### Get Remediation Plan

```http
GET /api/audit/remediation-plans/:id
```

#### Create Remediation Plan

```http
POST /api/audit/remediation-plans
Content-Type: application/json

{
  "findingId": "finding-uuid",
  "description": "Implement automated backup verification process",
  "scheduledStart": "2025-01-01",
  "scheduledEnd": "2025-03-31",
  "milestones": [
    {
      "title": "Evaluate backup verification tools",
      "dueDate": "2025-01-31",
      "description": "Research and select appropriate tooling"
    },
    {
      "title": "Implement verification scripts",
      "dueDate": "2025-02-28"
    },
    {
      "title": "Deploy to production",
      "dueDate": "2025-03-15"
    }
  ],
  "resources": {
    "estimatedHours": 120,
    "team": ["IT Operations", "Security"]
  }
}
```

#### Update Remediation Plan

```http
PUT /api/audit/remediation-plans/:id
Content-Type: application/json
```

#### Get Remediation Plan for Finding

```http
GET /api/audit/findings/:findingId/remediation-plan
```

#### Delete Remediation Plan

```http
DELETE /api/audit/remediation-plans/:id
```

### Test Procedures

Control testing procedures with sample selection and effectiveness assessment.

#### List Test Procedures for Audit

```http
GET /api/audits/:auditId/test-procedures?testType=inspection
```

**Query Parameters**:
- `controlId`: Filter by control
- `testType`: Filter by type (inquiry, observation, inspection, reperformance)
- `conclusion`: Filter by conclusion (effective, ineffective, na)
- `page`, `limit`: Pagination

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "procedureNumber": "TP-001",
      "title": "User Access Provisioning Test",
      "testType": "inspection",
      "controlId": "CC6.1-02",
      "sampleSize": 25,
      "sampleSelection": "Random sample of new hires from Q3 2024",
      "conclusion": "effective",
      "testedBy": "user-uuid",
      "testedAt": "2024-12-05T14:00:00Z"
    }
  ],
  "total": 28
}
```

#### Get Test Procedure

```http
GET /api/audits/:auditId/test-procedures/:id
```

**Response**: `200 OK`

```json
{
  "id": "uuid",
  "procedureNumber": "TP-001",
  "title": "User Access Provisioning Test",
  "description": "Verify that user access is provisioned according to policy",
  "testType": "inspection",
  "controlId": "CC6.1-02",
  "sampleSize": 25,
  "sampleSelection": "Random sample of new hires from Q3 2024",
  "expectedResult": "All sampled users should have approved access requests with manager sign-off",
  "actualResult": "24 of 25 samples met criteria. 1 exception noted - see finding F-003",
  "conclusion": "effective",
  "attachments": [...]
}
```

#### Create Test Procedure

```http
POST /api/audits/:auditId/test-procedures
Content-Type: application/json

{
  "procedureNumber": "TP-002",
  "title": "Password Policy Verification",
  "description": "Verify password complexity requirements are enforced",
  "testType": "reperformance",
  "controlId": "CC6.1-03",
  "sampleSize": 10,
  "expectedResult": "System should reject passwords that do not meet complexity requirements"
}
```

#### Update Test Procedure

```http
PUT /api/audits/:auditId/test-procedures/:id
Content-Type: application/json

{
  "actualResult": "All 10 test passwords were correctly rejected",
  "conclusion": "effective"
}
```

#### Delete Test Procedure

```http
DELETE /api/audits/:auditId/test-procedures/:id
```

### Audit Analytics

Analytics and trend analysis for audit performance.

#### Get Audit Trends

```http
GET /api/audit/analytics/trends?period=ytd
```

**Query Parameters**:
- `period`: Time period (mtd, qtd, ytd, all)
- `auditType`: Filter by audit type

**Response**: `200 OK`

```json
{
  "auditsCompleted": {
    "current": 12,
    "previous": 10,
    "change": 20
  },
  "averageDuration": {
    "current": 45,
    "previous": 52,
    "change": -13.5
  },
  "findingsPerAudit": {
    "current": 8.2,
    "previous": 9.5,
    "change": -13.7
  },
  "trendData": [
    { "month": "2024-01", "audits": 3, "findings": 24 },
    { "month": "2024-02", "audits": 2, "findings": 18 }
  ]
}
```

#### Get Finding Analytics

```http
GET /api/audit/analytics/findings?period=ytd&severity=high
```

**Query Parameters**:
- `period`: Time period
- `severity`: Filter by severity
- `category`: Filter by category

**Response**: `200 OK`

```json
{
  "byCategory": [
    { "category": "Access Control", "count": 45, "percentage": 32 },
    { "category": "Change Management", "count": 28, "percentage": 20 }
  ],
  "bySeverity": [
    { "severity": "critical", "count": 5 },
    { "severity": "high", "count": 18 },
    { "severity": "medium", "count": 42 },
    { "severity": "low", "count": 75 }
  ],
  "remediationMetrics": {
    "averageTimeToRemediate": 32,
    "openFindings": 23,
    "overdueFindings": 5
  }
}
```

#### Get Coverage Metrics

```http
GET /api/audit/analytics/coverage?framework=soc2
```

**Query Parameters**:
- `auditId`: Specific audit
- `framework`: Filter by framework

**Response**: `200 OK`

```json
{
  "controlsTested": 142,
  "totalControls": 156,
  "coveragePercentage": 91,
  "byCategory": [
    { "category": "CC1 - Control Environment", "tested": 15, "total": 15, "coverage": 100 },
    { "category": "CC6 - Logical Access", "tested": 22, "total": 25, "coverage": 88 }
  ],
  "gaps": [
    { "controlId": "CC6.8", "controlName": "Encryption Key Management", "reason": "Not in scope" }
  ]
}
```

### Audit Planning

Multi-year audit planning and resource allocation.

#### List Audit Plan Entries

```http
GET /api/audit/planning?year=2025&status=planned
```

**Query Parameters**:
- `year`: Filter by year
- `quarter`: Filter by quarter (1-4)
- `status`: Filter by status (planned, scheduled, in_progress, completed, deferred)
- `page`, `limit`: Pagination

**Response**: `200 OK`

```json
{
  "data": [
    {
      "id": "uuid",
      "year": 2025,
      "quarter": 1,
      "auditName": "SOC 2 Type II Annual Audit",
      "auditType": "soc2",
      "scope": "Security and Availability TSCs",
      "riskRating": "high",
      "estimatedHours": 400,
      "assignedTeam": ["John Smith", "Jane Doe"],
      "status": "scheduled",
      "linkedAuditId": null
    }
  ],
  "total": 24,
  "summary": {
    "totalPlanned": 24,
    "totalHours": 2400,
    "byQuarter": {
      "Q1": { "count": 6, "hours": 600 },
      "Q2": { "count": 7, "hours": 650 }
    }
  }
}
```

#### Get Audit Plan Entry

```http
GET /api/audit/planning/:id
```

#### Create Audit Plan Entry

```http
POST /api/audit/planning
Content-Type: application/json

{
  "year": 2025,
  "quarter": 2,
  "auditName": "HIPAA Annual Assessment",
  "auditType": "hipaa",
  "scope": "PHI handling and security controls",
  "riskRating": "high",
  "estimatedHours": 200,
  "assignedTeam": ["Auditor 1", "Auditor 2"],
  "notes": "Focus on new telehealth platform"
}
```

#### Update Audit Plan Entry

```http
PUT /api/audit/planning/:id
Content-Type: application/json

{
  "status": "in_progress",
  "linkedAuditId": "actual-audit-uuid"
}
```

#### Delete Audit Plan Entry

```http
DELETE /api/audit/planning/:id
```

### Audit Reports

Report generation and templates.

#### Generate Audit Report

```http
POST /api/audits/:auditId/reports/generate
Content-Type: application/json

{
  "type": "full" | "executive_summary" | "findings_only" | "management_letter",
  "format": "pdf" | "word" | "html"
}
```

**Response**: `200 OK` with file download

#### Get Report Templates

```http
GET /api/audit/reports/templates
```

**Response**: `200 OK`

```json
{
  "templates": [
    {
      "id": "full-report",
      "name": "Full Audit Report",
      "description": "Comprehensive report with all sections",
      "sections": ["executive_summary", "scope", "methodology", "findings", "recommendations", "appendices"]
    },
    {
      "id": "executive-summary",
      "name": "Executive Summary",
      "description": "High-level summary for leadership"
    },
    {
      "id": "management-letter",
      "name": "Management Letter",
      "description": "Formal letter to management with key findings"
    }
  ]
}
```

---

## AI Service

Base path: `/api/ai`

### AI Configuration

#### Get AI Configuration

```http
GET /api/ai/config
```

**Response**: `200 OK`

```json
{
  "provider": "anthropic",
  "model": "claude-opus-4-5-20250514",
  "enabledFeatures": {
    "riskScoring": true,
    "autoCategorization": true,
    "smartSearch": true,
    "policyGeneration": false,
    "controlMapping": true
  }
}
```

#### Update AI Configuration

```http
PUT /api/ai/config
Content-Type: application/json

{
  "provider": "openai",
  "model": "gpt-5",
  "apiKey": "sk-...",
  "temperature": 0.3,
  "enabledFeatures": {
    "riskScoring": true,
    "autoCategorization": true,
    "smartSearch": true,
    "policyGeneration": true,
    "controlMapping": true
  }
}
```

### AI Risk Scoring

#### Get Risk Scoring Suggestions

```http
POST /api/ai/risk-scoring
Content-Type: application/json

{
  "riskTitle": "Data Breach via SQL Injection",
  "riskDescription": "Attackers could exploit SQL injection vulnerabilities to access sensitive customer data",
  "category": "security",
  "existingControls": ["Web Application Firewall", "Input Validation"],
  "businessContext": "E-commerce platform processing 100k transactions daily"
}
```

**Response**: `200 OK`

```json
{
  "suggestedLikelihood": 3,
  "suggestedImpact": 5,
  "likelihoodRationale": "SQL injection remains a common attack vector. While WAF and input validation provide protection, the high transaction volume increases exposure.",
  "impactRationale": "A data breach affecting customer PII would result in regulatory penalties, reputational damage, and potential class action lawsuits.",
  "suggestedMitigations": [
    "Implement parameterized queries across all database interactions",
    "Deploy runtime application self-protection (RASP)",
    "Conduct regular penetration testing"
  ],
  "relatedRisks": ["Credential Stuffing", "API Security", "Third-Party Data Exposure"],
  "confidenceScore": 0.87
}
```

### AI Auto-Categorization

#### Categorize Entity

```http
POST /api/ai/categorize
Content-Type: application/json

{
  "title": "Annual Security Training",
  "description": "All employees must complete security awareness training annually covering phishing, social engineering, and data handling.",
  "entityType": "control",
  "availableCategories": ["access_control", "security_awareness", "data_protection", "incident_response"]
}
```

**Response**: `200 OK`

```json
{
  "suggestedCategory": "security_awareness",
  "alternativeCategories": [
    { "category": "data_protection", "confidence": 0.65 }
  ],
  "rationale": "This control focuses on employee training for security awareness topics.",
  "suggestedTags": ["training", "phishing", "social-engineering", "annual"],
  "confidenceScore": 0.94
}
```

### AI Smart Search

#### Natural Language Search

```http
POST /api/ai/search
Content-Type: application/json

{
  "query": "What controls do we have for protecting customer payment data?",
  "searchIn": ["controls", "policies", "evidence"],
  "limit": 10
}
```

**Response**: `200 OK`

```json
{
  "interpretedQuery": "Payment data protection controls, PCI DSS compliance, encryption, tokenization",
  "results": [
    {
      "id": "uuid",
      "type": "control",
      "title": "Payment Card Data Encryption",
      "description": "All payment card data is encrypted using AES-256...",
      "relevanceScore": 0.95,
      "matchReason": "Directly addresses payment data protection with encryption"
    }
  ],
  "suggestedQueries": [
    "PCI DSS compliance status",
    "Payment processor security assessments"
  ],
  "totalResults": 15
}
```

### AI Policy Drafting

#### Generate Policy Draft

```http
POST /api/ai/draft-policy
Content-Type: application/json

{
  "policyType": "Data Retention Policy",
  "companyName": "Acme Corp",
  "industry": "Healthcare",
  "complianceFrameworks": ["HIPAA", "SOC 2"],
  "additionalContext": "We store patient health records and need to comply with state-specific retention requirements"
}
```

**Response**: `200 OK`

```json
{
  "title": "Acme Corp Data Retention Policy",
  "content": "## 1. Purpose\n\nThis policy establishes data retention requirements...",
  "sections": ["Purpose", "Scope", "Definitions", "Retention Periods", "Disposal Procedures", "Exceptions", "Responsibilities"],
  "suggestedReviewers": ["Privacy Officer", "Legal Counsel", "Compliance Manager"],
  "complianceNotes": "This policy addresses HIPAA § 164.530(j) retention requirements and SOC 2 CC6.6 criteria."
}
```

---

## MCP Service

Base path: `/api/mcp`

### MCP Server Management

#### List Active Servers

```http
GET /api/mcp/servers
```

**Response**: `200 OK`

```json
{
  "servers": [
    {
      "id": "grc-evidence",
      "name": "GRC Evidence Collection",
      "status": "connected",
      "transport": "stdio",
      "capabilities": {
        "tools": [
          { "name": "collect_aws_evidence", "description": "Collect configuration evidence from AWS services" },
          { "name": "collect_github_evidence", "description": "Collect security evidence from GitHub repositories" }
        ],
        "resources": []
      },
      "lastConnected": "2025-12-08T10:30:00Z"
    }
  ]
}
```

#### Get Server Capabilities

```http
GET /api/mcp/servers/:id/capabilities
```

#### Connect Server

```http
POST /api/mcp/servers/:id/connect
```

#### Disconnect Server

```http
POST /api/mcp/servers/:id/disconnect
```

### MCP Tool Execution

#### Call Tool

```http
POST /api/mcp/tools/call
Content-Type: application/json

{
  "serverId": "grc-evidence",
  "toolName": "collect_aws_evidence",
  "args": {
    "service": "s3",
    "resourceId": null
  }
}
```

**Response**: `200 OK`

```json
{
  "service": "s3",
  "data": [
    {
      "Name": "production-data-bucket",
      "CreationDate": "2024-01-15T00:00:00Z"
    }
  ]
}
```

#### Access Resource

```http
POST /api/mcp/resources/access
Content-Type: application/json

{
  "serverId": "grc-evidence",
  "uri": "evidence://aws/s3/buckets"
}
```

### MCP Workflows

#### List Workflows

```http
GET /api/mcp/workflows
```

#### Create Workflow

```http
POST /api/mcp/workflows
Content-Type: application/json

{
  "name": "Daily Evidence Collection",
  "description": "Collect evidence from AWS and GitHub daily",
  "trigger": "schedule:daily",
  "steps": [
    {
      "id": "step-1",
      "name": "Collect AWS S3 Evidence",
      "serverId": "grc-evidence",
      "toolName": "collect_aws_evidence",
      "args": { "service": "s3" }
    },
    {
      "id": "step-2",
      "name": "Collect GitHub Branch Protection",
      "serverId": "grc-evidence",
      "toolName": "collect_github_evidence",
      "args": { "owner": "acme", "repo": "main-app", "evidenceType": "branch_protection" },
      "dependsOn": ["step-1"]
    }
  ]
}
```

#### Execute Workflow

```http
POST /api/mcp/workflows/:id/execute
Content-Type: application/json

{
  "initialContext": {
    "triggerReason": "manual"
  }
}
```

**Response**: `200 OK`

```json
{
  "workflowId": "uuid",
  "executionId": "exec-uuid",
  "status": "running",
  "startedAt": "2025-12-08T10:30:00Z"
}
```

#### Get Workflow Execution Status

```http
GET /api/mcp/workflows/:id/executions/:executionId
```

---

## Health Endpoints

All services expose standard health endpoints:

### Full Health Check

```http
GET /health
```

**Response**:

```json
{
  "status": "ok",
  "info": {
    "database": { "status": "up" },
    "memory_heap": { "status": "up" },
    "memory_rss": { "status": "up" }
  }
}
```

### Liveness Probe

```http
GET /health/live
```

For Kubernetes/Docker health checks:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 3001
  initialDelaySeconds: 30
  periodSeconds: 10
```

### Readiness Probe

```http
GET /health/ready
```

```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 3001
  initialDelaySeconds: 5
  periodSeconds: 5
```

---

## Webhooks

### Webhook Configuration

```http
POST /api/webhooks
Content-Type: application/json

{
  "url": "https://your-app.com/webhooks/grc",
  "events": [
    "control.created",
    "control.updated",
    "risk.status_changed",
    "policy.published"
  ],
  "secret": "your-webhook-secret"
}
```

### Webhook Events

| Event | Trigger |
|-------|---------|
| `control.created` | New control created |
| `control.updated` | Control updated |
| `control.deleted` | Control deleted |
| `risk.created` | New risk registered |
| `risk.status_changed` | Risk status changed |
| `policy.published` | Policy published |
| `evidence.expired` | Evidence expired |
| `audit.started` | Audit started |
| `audit.completed` | Audit completed |

### Webhook Payload

```json
{
  "event": "control.updated",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "id": "uuid",
    "title": "Access Control",
    "changes": {
      "status": {
        "old": "in_progress",
        "new": "implemented"
      }
    }
  },
  "signature": "sha256=..."
}
```

### Verifying Webhooks

```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}
```

---

## SDK Examples

### JavaScript/TypeScript

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://grc.example.com/api',
  headers: {
    'Authorization': `Bearer ${token}`,
    'x-user-id': userId,
    'x-organization-id': orgId,
  },
});

// List controls
const { data } = await api.get('/controls', {
  params: { status: 'implemented', limit: 50 }
});

// Create risk
const risk = await api.post('/risks', {
  title: 'New Risk',
  category: 'security',
  likelihood: 'likely',
  impact: 'major',
});
```

### Python

```python
import requests

class GRCClient:
    def __init__(self, base_url, token, user_id, org_id):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'x-user-id': user_id,
            'x-organization-id': org_id,
        }
    
    def list_controls(self, **params):
        return requests.get(
            f'{self.base_url}/controls',
            headers=self.headers,
            params=params
        ).json()
    
    def create_risk(self, data):
        return requests.post(
            f'{self.base_url}/risks',
            headers=self.headers,
            json=data
        ).json()

# Usage
client = GRCClient(
    'https://grc.example.com/api',
    token='...',
    user_id='...',
    org_id='...'
)
controls = client.list_controls(status='implemented')
```

---

## OpenAPI Specification

The full OpenAPI (Swagger) specification is available at:

- **Development**: `http://localhost:3001/api/docs`
- **Production**: `https://grc.example.com/api/docs`

To download the spec:

```bash
curl https://grc.example.com/api/docs-json > openapi.json
```


