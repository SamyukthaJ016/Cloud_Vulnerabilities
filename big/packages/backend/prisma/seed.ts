/**
 * Seed script — runs via `npm run prisma:seed`.
 *
 * Idempotent: every call upserts on unique keys, so it's safe to re-run.
 *
 * Owns:
 *   1. System roles (org_admin, org_member, viewer, scanner_operator)
 *   2. Permission catalog (mirror of src/modules/rbac/permissions.catalog.ts)
 *   3. RolePermission links per the catalog's role → permissions map
 *
 * Out of scope (separate tickets):
 *   4. Default plans (free, pro, enterprise) — billing module
 *   5. Scanner catalog rows — scanners module
 */
import { PrismaClient } from '@prisma/client';
import { PERMISSIONS, ROLE_PERMISSIONS } from '../src/modules/rbac/permissions.catalog';
import { SYSTEM_ROLE_KEYS } from '../src/common/enums';

const prisma = new PrismaClient();

const ROLE_DEFINITIONS: Array<{ key: string; name: string; description: string }> = [
  {
    key: SYSTEM_ROLE_KEYS.ORG_ADMIN,
    name: 'Organization admin',
    description: 'Full control of the organization: billing, members, scanners, secrets, scans.',
  },
  {
    key: SYSTEM_ROLE_KEYS.ORG_MEMBER,
    name: 'Member',
    description: 'Can run scans, view findings, and view billing.',
  },
  {
    key: SYSTEM_ROLE_KEYS.SCANNER_OPERATOR,
    name: 'Scanner operator',
    description: 'Can run scans and view findings; no settings or billing.',
  },
  {
    key: SYSTEM_ROLE_KEYS.VIEWER,
    name: 'Viewer',
    description: 'Read-only access to scans and findings.',
  },
];

async function seedPermissions() {
  for (const perm of Object.values(PERMISSIONS)) {
    await prisma.permission.upsert({
      where: { key: perm.key },
      create: perm,
      update: { resource: perm.resource, action: perm.action },
    });
  }
  console.log(`  permissions: ${Object.keys(PERMISSIONS).length} upserted`);
}

async function seedRoles() {
  for (const def of ROLE_DEFINITIONS) {
    await prisma.role.upsert({
      where: { key: def.key },
      create: { ...def, isSystem: true },
      update: { name: def.name, description: def.description, isSystem: true },
    });
  }
  console.log(`  roles: ${ROLE_DEFINITIONS.length} upserted`);
}

async function seedRolePermissions() {
  for (const [roleKey, permissions] of Object.entries(ROLE_PERMISSIONS)) {
    const role = await prisma.role.findUnique({ where: { key: roleKey } });
    if (!role) {
      console.warn(`  role '${roleKey}' missing — skipped`);
      continue;
    }

    // Wipe + re-insert so removing a permission from the catalog is reflected.
    await prisma.rolePermission.deleteMany({ where: { roleId: role.id } });

    for (const perm of permissions) {
      const permRow = await prisma.permission.findUnique({ where: { key: perm.key } });
      if (!permRow) continue;
      await prisma.rolePermission.create({
        data: { roleId: role.id, permissionId: permRow.id },
      });
    }
    console.log(`  role '${roleKey}': ${permissions.length} permissions linked`);
  }
}

async function main() {
  console.log('Seeding system catalog...');
  await seedPermissions();
  await seedRoles();
  await seedRolePermissions();
  console.log('Seed complete.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
