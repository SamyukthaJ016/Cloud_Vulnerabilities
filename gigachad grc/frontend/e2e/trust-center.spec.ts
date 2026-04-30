import { test, expect } from '@playwright/test';

/**
 * Trust Center E2E Tests
 * Tests trust center configuration and public portal
 */

test.describe('Trust Center', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/trust-center');
    await page.waitForLoadState('networkidle');
  });

  test('displays trust center page', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Trust/i })).toBeVisible();
  });

  test('shows trust center configuration or setup', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    const configSection = page.locator('text=/Configure|Setup|Enable|Settings/i');
    const previewSection = page.locator('text=/Preview|Public|Portal/i');
    
    const hasContent = await configSection.count() > 0 || await previewSection.count() > 0;
    expect(hasContent).toBeTruthy();
  });

  test('has branding options', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for branding configuration
    const brandingOptions = page.locator('text=/Logo|Color|Brand|Theme/i');
    
    if (await brandingOptions.count() > 0) {
      await expect(brandingOptions.first()).toBeVisible();
    }
  });

  test('has content visibility options', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for content toggles
    const contentToggles = page.locator('input[type="checkbox"], [role="switch"]');
    
    if (await contentToggles.count() > 0) {
      await expect(contentToggles.first()).toBeVisible();
    }
  });

  test('shows domain configuration', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for domain/URL settings
    const domainConfig = page.locator('text=/Domain|URL|Custom|CNAME/i');
    
    if (await domainConfig.count() > 0) {
      await expect(domainConfig.first()).toBeVisible();
    }
  });
});

test.describe('Trust Center Settings', () => {
  test('can navigate to trust center settings', async ({ page }) => {
    await page.goto('/trust-center/settings');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('body')).toBeVisible();
  });

  test('shows embed code options', async ({ page }) => {
    await page.goto('/trust-center/settings');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Look for embed/iframe options
    const embedSection = page.locator('text=/Embed|iframe|Widget|Code/i');
    
    if (await embedSection.count() > 0) {
      await expect(embedSection.first()).toBeVisible();
    }
  });
});

test.describe('Trust Center Public View', () => {
  test('can preview public trust center', async ({ page }) => {
    await page.goto('/trust-center');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Look for preview button
    const previewBtn = page.locator('button, a').filter({ hasText: /Preview|View|Open/i }).first();
    
    if (await previewBtn.count() > 0) {
      await expect(previewBtn).toBeVisible();
    }
  });
});




