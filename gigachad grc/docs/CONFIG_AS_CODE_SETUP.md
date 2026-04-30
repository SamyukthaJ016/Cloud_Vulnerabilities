# Configuration as Code - Setup Guide

## Database Migration

The Configuration as Code module requires database tables to be created. Run the following migration:

```bash
cd services/shared
npx prisma migrate dev --name add_config_as_code
```

Or if you prefer to use Prisma's auto-migration:

```bash
cd services/shared
npx prisma db push
```

This will create the following tables:
- `config_files` - Stores configuration files
- `config_file_versions` - Stores version history

## Initial Setup

1. **Enable the Module**
   - Navigate to Settings → Module Configuration
   - Enable "Configuration as Code"
   - Click "Save Configuration"

2. **Access the IDE**
   - Navigate to Settings → Configuration as Code
   - The IDE will automatically initialize with your current platform state

3. **Manual Initialization** (if needed)
   - If files don't appear automatically, click "Initialize from platform state" in the file explorer
   - This will export your current GRC resources as Terraform files

## File Structure

After initialization, you'll see:

```
controls/
  └── main.tf      # All controls
frameworks/
  └── main.tf      # All frameworks
policies/
  └── main.tf      # All policies
risks/
  └── main.tf      # All risks
vendors/
  └── main.tf      # All vendors
```

## Troubleshooting

### "No files yet" message persists

1. Check browser console for errors
2. Verify database migration was run successfully
3. Click "Initialize from platform state" button manually
4. Check backend logs for initialization errors

### Database errors

If you see errors about missing tables:
```bash
cd services/shared
npx prisma generate
npx prisma migrate dev
```

### Module not appearing

1. Ensure module is enabled in Settings → Module Configuration
2. Refresh the page (hard refresh: Cmd+Shift+R / Ctrl+Shift+R)
3. Check that `config-as-code` is in the enabled modules list

