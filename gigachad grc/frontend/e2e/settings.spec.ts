import { test, expect } from '@playwright/test';

/**
 * Settings Module E2E Tests
 * Tests for platform settings and configuration
 */

test.describe('Settings - Main Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
  });

  test('displays settings page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Setting/i })).toBeVisible();
  });

  test('shows settings sections/tabs', async ({ page }) => {
    // Look for settings navigation or sections
    const sections = page.locator('[class*="tab"], [class*="section"], [class*="nav"]');
    expect(await sections.count()).toBeGreaterThan(0);
  });
});

test.describe('Settings - User Management', () => {
  test('can navigate to user management', async ({ page }) => {
    await page.goto('/settings/users');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /User/i })).toBeVisible();
  });

  test('displays users list', async ({ page }) => {
    await page.goto('/settings/users');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const usersList = page.locator('table, [class*="list"]');
    await expect(usersList.first()).toBeVisible();
  });

  test('can add new user', async ({ page }) => {
    await page.goto('/settings/users');
    await page.waitForLoadState('networkidle');
    
    const addBtn = page.locator('button').filter({ hasText: /add|invite|create/i }).first();
    
    if (await addBtn.count() > 0) {
      await addBtn.click();
      await page.waitForTimeout(1000);
      
      const form = page.locator('form, [role="dialog"]');
      await expect(form.first()).toBeVisible();
    }
  });
});

test.describe('Settings - Permissions', () => {
  test('can navigate to permissions/groups', async ({ page }) => {
    await page.goto('/settings/permissions');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /Permission|Group|Role/i })).toBeVisible();
  });
});

test.describe('Settings - Employee Compliance', () => {
  test('can navigate to employee compliance settings', async ({ page }) => {
    await page.goto('/settings/employee-compliance');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /Employee.*Compliance|Compliance.*Configuration/i })).toBeVisible();
  });

  test('shows data source configuration', async ({ page }) => {
    await page.goto('/settings/employee-compliance');
    await page.waitForLoadState('networkidle');
    
    // Look for data source sections
    const dataSources = page.locator('text=/HRIS|Background.*Check|Training|MDM|Identity/i');
    expect(await dataSources.count()).toBeGreaterThan(0);
  });

  test('data source links navigate to integrations', async ({ page }) => {
    await page.goto('/settings/employee-compliance');
    await page.waitForLoadState('networkidle');
    
    // Click on a data source box
    const dataSourceBox = page.locator('[class*="card"], [class*="box"]').filter({ hasText: /HRIS|HR Tool/i }).first();
    
    if (await dataSourceBox.count() > 0) {
      await dataSourceBox.click();
      await page.waitForLoadState('networkidle');
      
      // Should navigate to integrations with search
      await expect(page).toHaveURL(/integrations/);
    }
  });
});

test.describe('Settings - Notifications', () => {
  test('can navigate to notification settings', async ({ page }) => {
    await page.goto('/settings/notifications');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /Notification/i })).toBeVisible();
  });
});

test.describe('Settings - Organization', () => {
  test('can navigate to organization settings', async ({ page }) => {
    await page.goto('/settings/organization');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /Organization/i })).toBeVisible();
  });

  test('shows organization form', async ({ page }) => {
    await page.goto('/settings/organization');
    await page.waitForLoadState('networkidle');
    
    const form = page.locator('form, input[name*="name"], input[placeholder*="name"]');
    await expect(form.first()).toBeVisible();
  });
});

test.describe('Settings - API Keys', () => {
  test('can navigate to API keys', async ({ page }) => {
    await page.goto('/settings/api-keys');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /API.*Key/i })).toBeVisible();
  });

  test('can create new API key', async ({ page }) => {
    await page.goto('/settings/api-keys');
    await page.waitForLoadState('networkidle');
    
    const createBtn = page.locator('button').filter({ hasText: /create|generate|add/i }).first();
    
    if (await createBtn.count() > 0) {
      await expect(createBtn).toBeVisible();
    }
  });
});

test.describe('Settings - Audit Log', () => {
  test('can navigate to audit log', async ({ page }) => {
    await page.goto('/settings/audit-log');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2, h3').filter({ hasText: /Audit.*Log/i })).toBeVisible();
  });

  test('displays audit log entries', async ({ page }) => {
    await page.goto('/settings/audit-log');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const logEntries = page.locator('table, [class*="log"], [class*="list"]');
    await expect(logEntries.first()).toBeVisible();
  });
});




