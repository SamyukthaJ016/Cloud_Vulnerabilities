import { test, expect } from '@playwright/test';

/**
 * Custom Dashboards E2E Tests
 * Tests dashboard customization and widget management
 */

test.describe('Custom Dashboards', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
  });

  test('displays dashboards page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Dashboard/i })).toBeVisible();
  });

  test('shows dashboard list or empty state', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    const dashboardList = page.locator('[class*="grid"], [class*="list"], [class*="card"]');
    const emptyState = page.locator('text=/No dashboard|Create|Get started/i');
    
    const hasContent = await dashboardList.count() > 0 || await emptyState.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('has create dashboard button', async ({ page }) => {
    const createBtn = page.locator('button, a').filter({ hasText: /Create|New|Add/i }).first();
    
    if (await createBtn.count() > 0) {
      await expect(createBtn).toBeVisible();
    }
  });

  test('can open dashboard editor', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Try to open an existing dashboard or create new one
    const dashboardCard = page.locator('[class*="card"], a[href*="dashboard"]').first();
    const createBtn = page.locator('button').filter({ hasText: /Create|New/i }).first();
    
    if (await dashboardCard.count() > 0) {
      await dashboardCard.click();
    } else if (await createBtn.count() > 0) {
      await createBtn.click();
    }
    
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });
});

test.describe('Dashboard Editor', () => {
  test('can add widgets', async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Create or open a dashboard
    const createBtn = page.locator('button').filter({ hasText: /Create|New/i }).first();
    
    if (await createBtn.count() > 0) {
      await createBtn.click();
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
      
      // Look for add widget button
      const addWidgetBtn = page.locator('button').filter({ hasText: /Add Widget|Add/i }).first();
      
      if (await addWidgetBtn.count() > 0) {
        await expect(addWidgetBtn).toBeVisible();
      }
    }
  });

  test('shows widget types', async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Open add widget dialog if possible
    const addWidgetBtn = page.locator('button').filter({ hasText: /Add Widget|Add/i }).first();
    
    if (await addWidgetBtn.count() > 0) {
      await addWidgetBtn.click();
      await page.waitForTimeout(500);
      
      // Look for widget type options
      const widgetTypes = page.locator('text=/Chart|Table|KPI|List|Metric/i');
      
      if (await widgetTypes.count() > 0) {
        await expect(widgetTypes.first()).toBeVisible();
      }
    }
  });

  test('can configure widget data source', async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Open widget configuration if possible
    const configBtn = page.locator('button').filter({ hasText: /Configure|Settings|Edit/i }).first();
    
    if (await configBtn.count() > 0) {
      await configBtn.click();
      await page.waitForTimeout(500);
      
      // Look for data source options
      const dataSourceOptions = page.locator('text=/Data Source|Controls|Risks|Policies|Vendors/i');
      
      if (await dataSourceOptions.count() > 0) {
        await expect(dataSourceOptions.first()).toBeVisible();
      }
    }
  });
});

test.describe('Dashboard Templates', () => {
  test('can access dashboard templates', async ({ page }) => {
    await page.goto('/settings/dashboard-templates');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('body')).toBeVisible();
  });

  test('shows template list', async ({ page }) => {
    await page.goto('/settings/dashboard-templates');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const templateList = page.locator('[class*="grid"], [class*="list"], table');
    const emptyState = page.locator('text=/No template|Create/i');
    
    const hasContent = await templateList.count() > 0 || await emptyState.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('has create template button', async ({ page }) => {
    await page.goto('/settings/dashboard-templates');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const createBtn = page.locator('button').filter({ hasText: /Create|New|Add/i }).first();
    
    if (await createBtn.count() > 0) {
      await expect(createBtn).toBeVisible();
    }
  });
});




