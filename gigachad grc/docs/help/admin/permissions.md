# Permission Groups

Permission Groups define what users can do within GigaChad GRC. This guide covers creating, managing, and assigning permission groups.

## Overview

The permissions system provides:
- Role-based access control (RBAC)
- Granular resource-level permissions
- Custom permission groups
- Easy user assignment

## Permission Model

### Resources
Permissions are organized by resource:

| Resource | Description |
|----------|-------------|
| `controls` | Security controls |
| `evidence` | Evidence artifacts |
| `policies` | Policy documents |
| `frameworks` | Compliance frameworks |
| `risk` | Risk register and analysis |
| `bcdr` | Business continuity |
| `audit_logs` | Audit trail |
| `users` | User management |
| `permissions` | Permission management |
| `settings` | System settings |
| `dashboard` | Dashboard access |
| `workspaces` | Workspace management |
| `reports` | Report generation |
| `ai` | AI features |

### Actions
Each resource supports these actions:

| Action | Description |
|--------|-------------|
| `create` | Create new items |
| `read` | View items |
| `update` | Modify items |
| `delete` | Remove items |
| `export` | Export data |
| `assign` | Assign ownership |

### Permission Format
Permissions are expressed as `resource:action`:
- `controls:read` - View controls
- `risk:create` - Create risks
- `settings:update` - Modify settings

## Default Permission Groups

### Administrator
Full platform access:
- All resources: All actions
- User management
- System configuration

### Compliance Manager
Manage compliance program:
- Controls: Full access
- Evidence: Full access
- Frameworks: Full access
- Policies: Full access
- Dashboard: Read
- Reports: Read, Export

### Risk Manager
Manage risk program:
- Risk: Full access
- BCDR: Full access
- Dashboard: Read
- Reports: Read, Export

### Auditor
Audit access:
- All resources: Read only
- Audit logs: Full access
- Reports: Read, Export

### Viewer
Basic read access:
- Dashboard: Read
- Controls: Read
- Evidence: Read
- Risk: Read

## Managing Permission Groups

### View Groups
Navigate to **Settings → Permissions**:
- List of all permission groups
- User count per group
- Description and permissions

### Create Group
1. Click **Create Group**
2. Enter:
   - **Name**: Group name
   - **Description**: What this group is for
3. Select permissions:
   - Check resources and actions
   - Or copy from existing group
4. Click **Create**

### Edit Group
1. Click on a group
2. Modify name, description, or permissions
3. Click **Save**

Changes apply immediately to all assigned users.

### Delete Group
1. Click group menu (⋮)
2. Select **Delete**
3. Reassign users if needed
4. Confirm deletion

## Assigning Users

### From Permission Group
1. Open a permission group
2. Go to **Members** tab
3. Click **Add Members**
4. Select users
5. Click **Add**

### From User Management
1. Go to **Settings → Users**
2. Edit a user
3. Go to **Permission Groups** tab
4. Check groups to assign
5. Save

## Effective Permissions

Users' effective permissions combine:
- All assigned permission groups
- Role-based defaults
- Workspace-specific overrides

### View Effective Permissions
1. Go to **Settings → Users**
2. Click on a user
3. Go to **Effective Permissions** tab
4. See complete permission list

### Permission Conflicts
When permissions overlap:
- Allow permissions are additive
- User gets union of all groups
- Most permissive wins

## Permission Matrix

View the complete permission matrix:
1. Go to **Settings → Permissions**
2. Click **View Matrix**
3. See all resources × actions × groups

Export for documentation or auditing.

## Workspace Permissions

If multi-workspace is enabled:

### Workspace-Level Groups
Create groups specific to workspaces:
1. Create group as usual
2. Enable **Workspace-scoped**
3. Assign to specific workspace

### Cross-Workspace Access
Some users need access across workspaces:
- Global admins
- Compliance officers
- Auditors

Configure in user's workspace assignments.

## API Permissions

For API access:
- API keys inherit user's permissions
- Can further restrict API key scope
- See **Settings → API Keys**

## Best Practices

### Principle of Least Privilege
- Grant minimum necessary access
- Start restrictive, add as needed
- Regular access reviews

### Group Naming
- Use clear, descriptive names
- Include team or function
- Avoid user-specific groups

### Documentation
- Document group purposes
- Keep description current
- Note business justification

### Review Cycle
- Quarterly permission reviews
- Remove unused groups
- Verify assignments still valid

## Troubleshooting

### User Missing Access
1. Check user's assigned groups
2. Verify group has required permission
3. Check effective permissions
4. Look for conflicting groups

### Too Much Access
1. Review all assigned groups
2. Remove unnecessary groups
3. Consider more restrictive group
4. Use workspace scoping

## Related Topics

- [User Management](users.md)
- [Organization Settings](organization.md)
- [API Keys](api-keys.md)
- [Workspaces](workspaces.md)

