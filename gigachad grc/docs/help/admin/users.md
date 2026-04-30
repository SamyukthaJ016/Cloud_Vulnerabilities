# User Management

Manage user accounts, invitations, and access across your GigaChad GRC platform.

## Overview

User Management allows administrators to:
- Invite new users to the platform
- Manage existing user accounts
- Assign roles and permissions
- Deactivate or remove users
- View user activity

## User List

Navigate to **Settings → Users** to see all users:

### Columns
- **Name**: User's display name
- **Email**: Login email address
- **Role**: Assigned role (Admin, User, Viewer, etc.)
- **Status**: Active, Pending, Deactivated
- **Last Login**: Most recent login date
- **Created**: Account creation date

### Filters
- **Status**: Active, Pending, Deactivated
- **Role**: Filter by role
- **Search**: Find by name or email

## Inviting Users

### Single Invitation
1. Click **Invite User**
2. Enter email address
3. Select role
4. (Optional) Add to permission groups
5. (Optional) Assign to workspaces
6. Click **Send Invitation**

### Bulk Invitation
1. Click **Invite User** → **Bulk Invite**
2. Download CSV template
3. Fill in user details
4. Upload completed CSV
5. Review and send invitations

### Invitation Email
Users receive an email with:
- Platform welcome message
- Account activation link
- Initial setup instructions

## User Roles

### Built-in Roles

| Role | Description |
|------|-------------|
| **Admin** | Full platform access, user management |
| **Compliance Manager** | Manage compliance program |
| **Risk Manager** | Manage risk program |
| **Auditor** | Audit-related access |
| **Viewer** | Read-only access |

### Custom Roles
Create custom roles via Permission Groups:
1. Go to **Settings → Permissions**
2. Create or edit a permission group
3. Assign users to the group

## Managing Users

### Edit User
1. Click on a user's name
2. Edit details:
   - Display name
   - Email (if allowed)
   - Role
   - Permission groups
   - Workspace assignments
3. Click **Save**

### Deactivate User
1. Click user's menu (⋮)
2. Select **Deactivate**
3. Confirm deactivation

Deactivated users:
- Cannot log in
- Data and history preserved
- Can be reactivated later

### Reactivate User
1. Filter to show deactivated users
2. Click user's menu (⋮)
3. Select **Reactivate**
4. User can log in again

### Delete User
1. Click user's menu (⋮)
2. Select **Delete**
3. Choose data handling:
   - Transfer assignments to another user
   - Leave unassigned
4. Confirm deletion

**Warning**: Deletion is permanent. Consider deactivating instead.

## User Profile

### User Detail View
Click any user to see:
- **Profile**: Basic information
- **Permissions**: Effective permissions
- **Activity**: Recent actions
- **Assignments**: Owned items

### User Activity
View user's recent actions:
- Logins
- Items created/modified
- Settings changed

## SSO Integration

If SSO is configured:

### Automatic User Creation
- Users created on first SSO login
- Attributes synced from identity provider
- Role assigned by default or mapped

### SSO User Management
- Users managed in identity provider
- Deactivation syncs from IdP
- Some fields may be read-only

## Multi-Workspace Users

If multi-workspace is enabled:

### Workspace Assignments
1. Edit user
2. Go to **Workspaces** tab
3. Check workspaces user should access
4. Set default workspace
5. Save

### Cross-Workspace Permissions
- Users can have different roles per workspace
- Admins can manage across all workspaces

## Security Settings

### Password Requirements
Configure in **Settings → Organization → Security**:
- Minimum length
- Complexity requirements
- Expiration period

### Multi-Factor Authentication
- Require MFA for all users
- User self-enrollment
- Admin can reset MFA

### Session Settings
- Session timeout duration
- Concurrent session limit
- Remember device option

## Audit Trail

All user management actions are logged:
- User creation
- Role changes
- Deactivations
- Permission changes

View in **Settings → Audit Log**.

## Best Practices

### Access Reviews
- Review user access quarterly
- Remove unnecessary access
- Verify role appropriateness

### Offboarding
- Deactivate immediately upon departure
- Transfer ownership of items
- Review audit logs

### Least Privilege
- Assign minimum necessary permissions
- Use specific permission groups
- Avoid over-granting admin access

## Troubleshooting

### User Can't Log In
1. Check user status (not deactivated?)
2. Verify email address
3. Reset password if needed
4. Check SSO configuration

### Missing Permissions
1. Review user's role
2. Check permission groups
3. Verify workspace assignments
4. Check effective permissions in user detail

## Related Topics

- [Permission Groups](permissions.md)
- [Organization Settings](organization.md)
- [Workspaces](workspaces.md)
- [Audit Logs](audit-logs.md)

