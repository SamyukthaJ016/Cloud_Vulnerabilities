# Configuration as Code Module

## Overview

A **Configuration as Code** module could be built into the platform that provides Terraform-like functionality for managing GRC resources declaratively. This would be more practical than building a separate Terraform provider.

## Feasibility Assessment

### ✅ **Highly Feasible** - Here's Why:

1. **Existing Infrastructure**
   - ✅ Module system already exists (can enable/disable modules)
   - ✅ REST APIs are ready (full CRUD for all resources)
   - ✅ Bulk import/export endpoints exist
   - ✅ Configuration management system in place
   - ✅ Organization-scoped settings already supported

2. **What Would Be Built**

A new module called **"Configuration as Code"** that provides:

- **Declarative Configuration Management**
  - Define GRC resources in YAML/JSON/Terraform format
  - Version control in Git
  - Sync from Git repositories
  - State management

- **Import/Export Capabilities**
  - Export current state to Terraform/YAML/JSON
  - Import configurations
  - Validate configurations
  - Apply changes (plan/apply workflow)

- **Terraform Compatibility**
  - Terraform-compatible API endpoints
  - State file management
  - Resource mapping

## Architecture

### Module Structure

```
services/config-as-code/
├── config-as-code.module.ts
├── config-as-code.controller.ts
├── config-as-code.service.ts
├── dto/
│   ├── config-import.dto.ts
│   ├── config-export.dto.ts
│   └── terraform-state.dto.ts
├── parsers/
│   ├── terraform-parser.ts
│   ├── yaml-parser.ts
│   └── json-parser.ts
├── state/
│   ├── state-manager.service.ts
│   └── state-storage.service.ts
└── sync/
    ├── git-sync.service.ts
    └── sync-scheduler.service.ts
```

### Key Features

#### 1. Configuration Import/Export

```typescript
// Export current state
POST /api/config-as-code/export
{
  "format": "terraform", // or "yaml", "json"
  "resources": ["controls", "frameworks", "policies"]
}

// Import configuration
POST /api/config-as-code/import
{
  "format": "terraform",
  "config": "...",
  "dryRun": true // Preview changes
}
```

#### 2. Terraform State Management

```typescript
// Get Terraform state
GET /api/config-as-code/terraform/state

// Update Terraform state
PUT /api/config-as-code/terraform/state
{
  "version": 4,
  "terraform_version": "1.5.0",
  "resources": [...]
}
```

#### 3. Git Sync

```typescript
// Configure Git sync
POST /api/config-as-code/git/sync
{
  "repository": "https://github.com/org/grc-config",
  "branch": "main",
  "path": "terraform/",
  "schedule": "0 2 * * *" // Cron schedule
}
```

## Implementation Approach

### Phase 1: Core Module (2-3 weeks)

**What's Built:**
- Module structure and basic endpoints
- YAML/JSON parser
- Export functionality (current state → config)
- Import functionality (config → apply changes)
- Basic state management

**Complexity:** ⭐⭐ (Medium)
- Leverages existing APIs
- Uses existing bulk operations
- Adds parsing and state tracking

### Phase 2: Terraform Compatibility (1-2 weeks)

**What's Built:**
- Terraform HCL parser
- Terraform state file management
- Resource mapping (Terraform resources → GRC resources)
- Terraform-compatible API endpoints

**Complexity:** ⭐⭐⭐ (Medium-High)
- Requires Terraform HCL parsing library
- Need to map Terraform concepts to GRC concepts
- State file format compatibility

### Phase 3: Git Integration (1-2 weeks)

**What's Built:**
- Git repository integration
- Scheduled sync
- Webhook support (sync on push)
- Conflict resolution

**Complexity:** ⭐⭐ (Medium)
- Uses existing Git libraries
- Leverages existing scheduler infrastructure

### Phase 4: Advanced Features (2-3 weeks)

**What's Built:**
- Plan/Apply workflow (preview changes)
- Drift detection (detect manual changes)
- Rollback capabilities
- Multi-environment support

**Complexity:** ⭐⭐⭐ (Medium-High)
- Requires change tracking
- State comparison logic

## Example Usage

### As a Platform Module

```typescript
// Enable the module
PUT /api/modules
{
  "enabledModules": [..., "config-as-code"]
}

// Export current configuration
GET /api/config-as-code/export?format=terraform

// Import from Git
POST /api/config-as-code/git/sync
{
  "repository": "https://github.com/myorg/grc-config",
  "autoSync": true
}
```

### Configuration File Format

**Terraform Format:**
```hcl
resource "gigachad_grc_control" "access_control" {
  name        = "Access Control Policy"
  category    = "Access Control"
  description = "Controls for managing user access"
  framework_id = "soc2-framework-id"
  status      = "implemented"
}
```

**YAML Format:**
```yaml
controls:
  - name: "Access Control Policy"
    category: "Access Control"
    description: "Controls for managing user access"
    framework_id: "soc2-framework-id"
    status: "implemented"
```

## Benefits of Building as a Module

### ✅ Advantages

1. **Integrated Experience**
   - Works seamlessly with existing platform
   - Uses existing authentication/authorization
   - Leverages existing APIs
   - No external dependencies

2. **Easier to Maintain**
   - Single codebase
   - Shared infrastructure
   - Consistent patterns
   - Built-in audit logging

3. **Better User Experience**
   - UI for configuration management
   - Visual diff/preview
   - Error handling and validation
   - Integrated with existing workflows

4. **Faster Development**
   - Reuse existing services
   - Leverage existing bulk operations
   - Use existing module system
   - No need for separate provider development

### ⚠️ Considerations

1. **Terraform Provider Still Needed**
   - If customers want to use Terraform CLI directly
   - For integration with Terraform Cloud/Enterprise
   - For existing Terraform workflows

2. **Two Approaches Can Coexist**
   - Platform module for integrated experience
   - Terraform provider for CLI/CI/CD integration
   - Both use same underlying APIs

## Recommended Approach

### Option A: Platform Module (Recommended)

**Build a "Configuration as Code" module** that provides:
- ✅ Declarative configuration management
- ✅ Import/export capabilities
- ✅ Git sync
- ✅ Terraform-compatible formats
- ✅ Integrated UI

**Timeline:** 6-8 weeks
**Complexity:** Medium
**Value:** High (integrated, easier to use)

### Option B: Terraform Provider (Alternative)

**Build a separate Terraform provider** that:
- ✅ Works with Terraform CLI
- ✅ Integrates with Terraform Cloud
- ✅ Follows Terraform standards
- ❌ Requires separate maintenance
- ❌ Less integrated with platform

**Timeline:** 8-12 weeks
**Complexity:** Medium-High
**Value:** Medium (requires Terraform knowledge)

### Option C: Both (Best of Both Worlds)

**Build both:**
1. Platform module for integrated experience
2. Terraform provider for CLI/CI/CD

**Timeline:** 10-14 weeks
**Complexity:** High
**Value:** Highest (covers all use cases)

## Implementation Priority

### Must Have (MVP)
- ✅ Export current state to YAML/JSON
- ✅ Import configuration from YAML/JSON
- ✅ Basic validation
- ✅ Error reporting

### Should Have (v1.0)
- ✅ Terraform format support
- ✅ State management
- ✅ Plan/Apply workflow
- ✅ Git sync

### Nice to Have (v2.0)
- ✅ Drift detection
- ✅ Rollback capabilities
- ✅ Multi-environment support
- ✅ Visual diff UI

## Conclusion

**Yes, this is absolutely feasible and would be easier than building a separate Terraform provider.**

The platform already has:
- ✅ Module system
- ✅ REST APIs
- ✅ Bulk operations
- ✅ Configuration management

Building a "Configuration as Code" module would:
- ✅ Leverage existing infrastructure
- ✅ Provide integrated experience
- ✅ Be easier to maintain
- ✅ Offer better UX

**Recommendation:** Start with the platform module approach. It's faster to build, easier to maintain, and provides better integration. If customers need Terraform CLI support later, a provider can be built that uses the same APIs.

