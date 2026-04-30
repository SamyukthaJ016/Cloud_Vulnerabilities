# Workspaces

Workspaces allow you to segment your GRC data within a single organization. This guide covers creating, managing, and using workspaces.

## Overview

Workspaces provide:
- Data isolation between business units
- Separate compliance programs
- User access control per workspace
- Cross-workspace reporting

## When to Use Workspaces

### Good Use Cases
- Multiple business units with separate compliance needs
- Different geographic regions with distinct requirements
- Acquired companies requiring separate tracking
- Dev/staging/production separation

### Consider Alternatives
- For role-based access, use Permission Groups instead
- For project separation, use tags/categories
- For complete isolation, use separate organizations

## Enabling Multi-Workspace

### Enable the Feature
1. Go to **Settings → Organization**
2. Find **Multi-Workspace Mode**
3. Toggle to **Enabled**
4. Confirm the action

### Initial Setup
After enabling:
- A default workspace is created
- Existing data moves to the default workspace
- Users are assigned to the default workspace

## Managing Workspaces

### View Workspaces
Navigate to **Settings → Workspaces** to see all workspaces:

| Column | Description |
|--------|-------------|
| Name | Workspace name |
| Description | Purpose description |
| Users | Number of assigned users |
| Items | Count of items in workspace |
| Created | Creation date |

### Create Workspace
1. Click **Create Workspace**
2. Enter:
   - **Name**: Workspace name (required)
   - **Description**: Purpose and scope
   - **Slug**: URL-friendly identifier
3. Click **Create**

### Edit Workspace
1. Click on a workspace
2. Modify details
3. Click **Save**

### Delete Workspace
1. Click workspace menu (⋮)
2. Select **Delete**
3. Choose data handling:
   - Move data to another workspace
   - Delete all data (permanent)
4. Confirm deletion

**Warning**: Deletion is permanent. Export data first if needed.

## Workspace Switching

### Default Workspace
Each user has a default workspace:
- Loads automatically on login
- Can be changed in user profile
- Set by admin during invitation

### Switch Workspaces
1. Click the workspace dropdown in the header
2. Select the desired workspace
3. Platform reloads with new context

### Workspace Indicator
The current workspace appears:
- In the header
- In breadcrumbs
- On exported reports

## User Assignment

### Assign Users to Workspace
1. Open workspace details
2. Go to **Users** tab
3. Click **Add Users**
4. Select users
5. Click **Add**

### Remove Users
1. In workspace users list
2. Click user menu (⋮)
3. Select **Remove from Workspace**

### Bulk Assignment
1. Go to **Settings → Users**
2. Select multiple users
3. Click **Bulk Actions**
4. Select **Add to Workspace**
5. Choose workspace

## Data Isolation

### What's Isolated
Each workspace has separate:
- Controls
- Risks
- Evidence
- Policies
- Vendors
- Audits
- Custom dashboards

### Shared Across Workspaces
Some items are organization-wide:
- Users (but assignments vary)
- Permission groups
- Organization settings
- Integration configurations
- Framework definitions

## Cross-Workspace Access

### Global Administrators
Users with admin role can:
- View all workspaces
- Switch between any workspace
- Access cross-workspace reports

### Cross-Workspace Reports
Generate reports spanning multiple workspaces:
1. Go to **Tools → Reports**
2. Select **Cross-Workspace Report**
3. Choose workspaces to include
4. Generate report

## Workspace Settings

### Per-Workspace Configuration
Each workspace can have:
- Custom notification settings
- Specific integrations
- Unique dashboards
- Local administrators

### Access Settings
1. Open workspace details
2. Go to **Settings** tab
3. Configure workspace-specific options

## Migration Between Workspaces

### Move Items
Move items from one workspace to another:
1. Select items in the source workspace
2. Click **Move to Workspace**
3. Select destination workspace
4. Confirm move

### Bulk Move
For large migrations:
1. Export data from source workspace
2. Import into destination workspace
3. Verify data integrity
4. Delete from source

## Best Practices

### Naming Convention
- Use clear, consistent names
- Include region/unit identifier
- Avoid abbreviations

### Documentation
- Document workspace purpose
- Maintain assignment records
- Note any special configurations

### Access Management
- Review assignments regularly
- Minimize cross-workspace access
- Use dedicated workspace admins

### Data Hygiene
- Regular cleanup of unused workspaces
- Archive inactive workspaces
- Consistent data standards across workspaces

## Troubleshooting

### User Can't See Workspace
1. Verify user is assigned to workspace
2. Check user's permissions
3. Ensure workspace is active

### Data Not Appearing
1. Verify correct workspace is selected
2. Check data filters
3. Confirm data exists in this workspace

### Cross-Workspace Issues
1. Verify admin permissions
2. Check workspace-specific settings
3. Review cross-workspace report configuration

## Related Topics

- [User Management](users.md)
- [Organization Settings](organization.md)
- [Permission Groups](permissions.md)

