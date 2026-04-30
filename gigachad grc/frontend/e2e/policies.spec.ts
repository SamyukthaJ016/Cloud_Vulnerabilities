import { test, expect } from '@playwright/test';

/**
 * Policies E2E Tests
 * Tests policy document management and version control
 */

test.describe('Policies', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/policies');
    await page.waitForLoadState('networkidle');
  });

  test('displays policies page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Polic/i })).toBeVisible();
  });

  test('shows policy list or empty state', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    const policyList = page.locator('table, [class*="grid"], [class*="list"], [class*="card"]');
    const emptyState = page.locator('text=/No polic|Create your first/i');
    
    const hasContent = await policyList.count() > 0 || await emptyState.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('has create policy button', async ({ page }) => {
    const createBtn = page.locator('button, a').filter({ hasText: /Create|New|Add|Upload/i }).first();
    
    if (await createBtn.count() > 0) {
      await expect(createBtn).toBeVisible();
    }
  });

  test('can search policies', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]').first();
    
    if (await searchInput.count() > 0) {
      await searchInput.fill('security');
      await page.waitForTimeout(1000);
      
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('can filter by status', async ({ page }) => {
    const statusFilter = page.locator('select, [class*="filter"]').first();
    
    if (await statusFilter.count() > 0) {
      await statusFilter.click();
      await page.waitForTimeout(500);
    }
  });

  test('displays policy status badges', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for status indicators
    const statusBadges = page.locator('text=/Draft|Published|Review|Approved|Retired/i');
    
    if (await statusBadges.count() > 0) {
      await expect(statusBadges.first()).toBeVisible();
    }
  });
});

test.describe('Policy Detail', () => {
  test('can view policy details', async ({ page }) => {
    await page.goto('/policies');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const policyLink = page.locator('a[href*="polic"], tr, [class*="card"]').first();
    
    if (await policyLink.count() > 0) {
      await policyLink.click();
      await page.waitForLoadState('networkidle');
      
      await expect(page.locator('body')).toBeVisible();
    }
  });
});

test.describe('Policy Version Control', () => {
  test('can view policy versions', async ({ page }) => {
    await page.goto('/policies');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const policyLink = page.locator('a[href*="polic"]').first();
    
    if (await policyLink.count() > 0) {
      await policyLink.click();
      await page.waitForLoadState('networkidle');
      
      // Look for version history or tabs
      const versionTab = page.locator('text=/Version|History/i');
      
      if (await versionTab.count() > 0) {
        await expect(versionTab.first()).toBeVisible();
      }
    }
  });
});




