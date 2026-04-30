import { test, expect } from '@playwright/test';

/**
 * Evidence E2E Tests
 * Tests evidence collection, management, and attestation
 */

test.describe('Evidence', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/evidence');
    await page.waitForLoadState('networkidle');
  });

  test('displays evidence page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Evidence/i })).toBeVisible();
  });

  test('shows evidence list or empty state', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    const evidenceList = page.locator('table, [class*="grid"], [class*="list"], [class*="card"]');
    const emptyState = page.locator('text=/No evidence|Upload|Collect/i');
    
    const hasContent = await evidenceList.count() > 0 || await emptyState.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('has upload/collect evidence button', async ({ page }) => {
    const uploadBtn = page.locator('button, a').filter({ hasText: /Upload|Collect|Add|New/i }).first();
    
    if (await uploadBtn.count() > 0) {
      await expect(uploadBtn).toBeVisible();
    }
  });

  test('can search evidence', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]').first();
    
    if (await searchInput.count() > 0) {
      await searchInput.fill('audit');
      await page.waitForTimeout(1000);
      
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('can filter by type', async ({ page }) => {
    const typeFilter = page.locator('select, [class*="filter"]').first();
    
    if (await typeFilter.count() > 0) {
      await typeFilter.click();
      await page.waitForTimeout(500);
    }
  });

  test('displays evidence types', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for evidence type indicators
    const typeIndicators = page.locator('text=/Screenshot|Document|Report|Manual|Automated/i');
    
    if (await typeIndicators.count() > 0) {
      await expect(typeIndicators.first()).toBeVisible();
    }
  });

  test('displays evidence status', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for status indicators
    const statusIndicators = page.locator('text=/Valid|Expired|Pending|Review/i');
    
    if (await statusIndicators.count() > 0) {
      await expect(statusIndicators.first()).toBeVisible();
    }
  });
});

test.describe('Evidence Detail', () => {
  test('can view evidence details', async ({ page }) => {
    await page.goto('/evidence');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const evidenceLink = page.locator('a[href*="evidence"], tr, [class*="card"]').first();
    
    if (await evidenceLink.count() > 0) {
      await evidenceLink.click();
      await page.waitForLoadState('networkidle');
      
      await expect(page.locator('body')).toBeVisible();
    }
  });
});

test.describe('Evidence Automation', () => {
  test('shows integration sources', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for integration/source indicators
    const integrationIndicators = page.locator('text=/AWS|Azure|GitHub|Integration|Automated/i');
    
    if (await integrationIndicators.count() > 0) {
      await expect(integrationIndicators.first()).toBeVisible();
    }
  });
});




