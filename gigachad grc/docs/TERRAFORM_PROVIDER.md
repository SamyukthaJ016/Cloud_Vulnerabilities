# Terraform Provider for GigaChad GRC

## Current State

**Short Answer**: The platform currently has Terraform for **infrastructure deployment** (AWS resources), but **does not yet have a Terraform provider** for managing **GRC data** (frameworks, controls, policies, etc.).

## What Exists Today

### ✅ Infrastructure as Code (IaC)
The platform includes comprehensive Terraform configurations for deploying the infrastructure:

- **Location**: `terraform/` directory
- **Purpose**: Deploy AWS infrastructure (VPC, ECS, RDS, Redis, S3, ALB)
- **Resources**: ~50-70 AWS resources managed via Terraform
- **Status**: ✅ Production-ready

### ❌ GRC Data Management via Terraform
Currently, GRC data must be managed through:
- Web UI
- REST API calls (manual or scripts)
- Bulk import endpoints (CSV/JSON)

## API Readiness for Terraform

The platform **does have RESTful APIs** that could support a Terraform provider:

### Controls API (`/api/controls`)
- ✅ `GET /api/controls` - List controls
- ✅ `GET /api/controls/:id` - Get control
- ✅ `POST /api/controls` - Create control
- ✅ `PUT /api/controls/:id` - Update control
- ✅ `DELETE /api/controls/:id` - Delete control
- ✅ `POST /api/controls/bulk` - Bulk upload

### Frameworks API (`/api/frameworks`)
- ✅ `GET /api/frameworks` - List frameworks
- ✅ `GET /api/frameworks/:id` - Get framework
- ✅ `POST /api/frameworks` - Create framework (if custom)
- ✅ `PUT /api/frameworks/:id` - Update framework
- ✅ `DELETE /api/frameworks/:id` - Delete framework

### Other APIs
- ✅ Risks (`/api/risks`)
- ✅ Evidence (`/api/evidence`)
- ✅ Policies (`/api/policies`)
- ✅ Vendors (`/api/vendors`)
- ✅ Integrations (`/api/integrations`)

## What Would Be Needed

To enable Terraform management of GRC data, you would need:

### 1. Terraform Provider Development

A custom Terraform provider that implements:

```hcl
terraform {
  required_providers {
    gigachad-grc = {
      source  = "gigachad/grc"
      version = "~> 1.0"
    }
  }
}

provider "gigachad-grc" {
  api_url      = "https://your-grc-instance.com"
  api_key      = var.grc_api_key
  organization = "your-org-id"
}

# Example: Manage a control
resource "gigachad_grc_control" "access_control" {
  name        = "Access Control Policy"
  category    = "Access Control"
  description = "Controls for managing user access"
  framework_id = gigachad_grc_framework.soc2.id
  status      = "implemented"
}

# Example: Manage a framework
resource "gigachad_grc_framework" "soc2" {
  name        = "SOC 2 Type II"
  type        = "soc2"
  version     = "2024"
  description = "SOC 2 Type II compliance framework"
}
```

### 2. Provider Requirements

The provider would need to:

1. **Authentication**
   - Support API key authentication
   - Support OAuth2 token authentication
   - Handle organization scoping

2. **Resource Management**
   - Implement CRUD operations for each resource type
   - Handle relationships (controls → frameworks, evidence → controls)
   - Support bulk operations

3. **State Management**
   - Track resource state
   - Handle drift detection
   - Support import of existing resources

4. **Error Handling**
   - Graceful handling of API errors
   - Retry logic for transient failures
   - Validation error reporting

## Implementation Approach

### Option 1: Build Custom Provider (Recommended)

Create a Terraform provider using the [Terraform Plugin SDK](https://www.terraform.io/plugin/sdkv2):

**Structure:**
```
terraform-provider-gigachad-grc/
├── main.go
├── provider.go
├── resource_control.go
├── resource_framework.go
├── resource_policy.go
├── resource_risk.go
└── client/
    └── api_client.go
```

**Key Components:**
- Provider configuration
- Resource schemas
- CRUD operations
- API client wrapper

### Option 2: Use Terraform HTTP Provider

Use the [terraform-provider-http](https://registry.terraform.io/providers/hashicorp/http/latest) for simpler use cases:

```hcl
provider "http" {}

data "http" "create_control" {
  url    = "https://api.example.com/api/controls"
  method = "POST"
  headers = {
    Authorization = "Bearer ${var.api_token}"
  }
  request_body = jsonencode({
    name = "My Control"
    category = "Access Control"
  })
}
```

**Limitations:**
- No state management
- Manual drift detection
- More verbose configuration

### Option 3: Use External Data Source + Local Provisioner

Combine Terraform with external scripts:

```hcl
data "external" "create_control" {
  program = ["bash", "scripts/create-control.sh"]
  query = {
    name     = "My Control"
    category = "Access Control"
  }
}
```

## Benefits of Terraform Provider

1. **Version Control**: Track GRC configuration in Git
2. **Infrastructure as Code**: Manage compliance program declaratively
3. **Environment Parity**: Ensure dev/staging/prod consistency
4. **Change Management**: Review changes via pull requests
5. **Automation**: Integrate with CI/CD pipelines
6. **Audit Trail**: Track all changes in Git history

## Example Use Cases

### Use Case 1: Multi-Environment Management

```hcl
# environments/dev/controls.tf
module "dev_controls" {
  source = "../../modules/controls"
  environment = "dev"
}

# environments/prod/controls.tf
module "prod_controls" {
  source = "../../modules/controls"
  environment = "prod"
}
```

### Use Case 2: Framework Migration

```hcl
# Migrate controls from one framework to another
resource "gigachad_grc_control" "migrated" {
  for_each = var.controls_to_migrate
  
  name        = each.value.name
  category    = each.value.category
  framework_id = gigachad_grc_framework.new_framework.id
  source_control_id = each.value.source_id
}
```

### Use Case 3: Policy as Code

```hcl
# Define policies in Terraform
resource "gigachad_grc_policy" "data_retention" {
  name        = "Data Retention Policy"
  category    = "Data Management"
  content     = file("policies/data-retention.md")
  approvers   = ["admin@example.com"]
  review_frequency = "annually"
}
```

## Next Steps

To implement Terraform provider support:

1. **Assess Priority**: Determine which resources are most critical
2. **Design Schema**: Define Terraform resource schemas
3. **Build Provider**: Implement provider using Terraform SDK
4. **Test**: Validate CRUD operations and state management
5. **Document**: Create examples and usage guides
6. **Publish**: Make provider available (Terraform Registry or private)

## Current Workaround

Until a Terraform provider is available, you can:

1. **Use API Scripts**: Create scripts that call the REST API
2. **Bulk Import**: Use CSV/JSON bulk upload endpoints
3. **GitOps**: Store configuration in Git and sync via CI/CD
4. **Terraform External Data**: Use external data sources with API calls

## API Authentication

The platform supports:
- ✅ API Key authentication (`x-api-key` header)
- ✅ OAuth2 Bearer tokens
- ✅ Organization-scoped access

All API endpoints are tenant-isolated and require proper authentication.

## Conclusion

While the platform has the **API foundation** needed for a Terraform provider, **the provider itself does not yet exist**. The REST APIs are well-structured and support full CRUD operations, making provider development feasible.

**Recommendation**: If Terraform-based GRC data management is a priority, consider building a custom provider or using the HTTP provider as an interim solution.

