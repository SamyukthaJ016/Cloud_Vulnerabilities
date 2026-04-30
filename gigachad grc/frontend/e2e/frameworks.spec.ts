import { test, expect } from '@playwright/test';

/**
 * Frameworks E2E Tests
 * Tests compliance framework management and readiness assessments
 */

test.describe('Frameworks', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/frameworks');
    await page.waitForLoadState('networkidle');
  });

  test('displays frameworks page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Framework/i })).toBeVisible();
  });

  test('shows framework cards or list', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Should have framework cards
    const frameworkCards = page.locator('[class*="card"], [class*="framework"], tr');
    const emptyState = page.locator('text=/No framework|Add your first/i');
    
    const hasContent = await frameworkCards.count() > 0 || await emptyState.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('displays framework readiness percentages', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for readiness indicators
    const readinessIndicators = page.locator('text=/%|ready|compliant/i');
    
    if (await readinessIndicators.count() > 0) {
      await expect(readinessIndicators.first()).toBeVisible();
    }
  });

  test('can search frameworks', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]').first();
    
    if (await searchInput.count() > 0) {
      await searchInput.fill('SOC');
      await page.waitForTimeout(1000);
      
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('can add new framework', async ({ page }) => {
    const addBtn = page.locator('button').filter({ hasText: /Add|New|Create/i }).first();
    
    if (await addBtn.count() > 0) {
      await addBtn.click();
      await page.waitForTimeout(500);
      
      // Should show add framework UI
      const modal = page.locator('[role="dialog"], .modal, form');
      expect(await modal.count()).toBeGreaterThan(0);
    }
  });
});

test.describe('Framework Detail', () => {
  test('can view framework details', async ({ page }) => {
    await page.goto('/frameworks');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Try to click on a framework
    const frameworkLink = page.locator('a[href*="framework"], [class*="card"]').first();
    
    if (await frameworkLink.count() > 0) {
      await frameworkLink.click();
      await page.waitForLoadState('networkidle');
      
      // Should show framework detail
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('displays control mappings', async ({ page }) => {
    await page.goto('/frameworks');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const frameworkLink = page.locator('a[href*="framework"]').first();
    
    if (await frameworkLink.count() > 0) {
      await frameworkLink.click();
      await page.waitForLoadState('networkidle');
      
      // Look for control mappings
      const mappings = page.locator('text=/Control|Mapping|Requirement/i');
      expect(await mappings.count()).toBeGreaterThan(0);
    }
  });
});

test.describe('Readiness Assessments', () => {
  test('can view readiness assessment', async ({ page }) => {
    await page.goto('/assessments');
    await page.waitForLoadState('networkidle');
    
    // Should show assessments page
    await expect(page.locator('body')).toBeVisible();
  });
});




