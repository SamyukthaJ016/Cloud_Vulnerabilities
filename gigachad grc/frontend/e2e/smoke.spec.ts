import { test, expect } from '@playwright/test';

/**
 * Smoke Tests - Basic navigation and page load verification
 * These tests verify that all main pages load without errors
 */

test.describe('Smoke Tests - Page Loading', () => {
  test('homepage loads successfully', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/GigaChad GRC|Dashboard/i);
  });

  test('dashboard loads with key elements', async ({ page }) => {
    await page.goto('/dashboard');
    
    // Wait for dashboard to load
    await page.waitForLoadState('networkidle');
    
    // Check for main dashboard elements
    await expect(page.locator('h1, h2').first()).toBeVisible();
    
    // No critical errors in console
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    
    // Wait a bit for any async errors
    await page.waitForTimeout(1000);
    expect(errors.filter(e => !e.includes('Warning'))).toHaveLength(0);
  });
});

test.describe('Smoke Tests - Navigation', () => {
  test('can navigate to Controls page', async ({ page }) => {
    await page.goto('/controls');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Controls/i })).toBeVisible();
  });

  test('can navigate to Frameworks page', async ({ page }) => {
    await page.goto('/frameworks');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Framework/i })).toBeVisible();
  });

  test('can navigate to Risks page', async ({ page }) => {
    await page.goto('/risks');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Risk/i })).toBeVisible();
  });

  test('can navigate to Policies page', async ({ page }) => {
    await page.goto('/policies');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Polic/i })).toBeVisible();
  });

  test('can navigate to Vendors page', async ({ page }) => {
    await page.goto('/vendors');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Vendor/i })).toBeVisible();
  });

  test('can navigate to Evidence page', async ({ page }) => {
    await page.goto('/evidence');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Evidence/i })).toBeVisible();
  });

  test('can navigate to Integrations page', async ({ page }) => {
    await page.goto('/integrations');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Integration/i })).toBeVisible();
  });

  test('can navigate to Audits page', async ({ page }) => {
    await page.goto('/audits');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Audit/i })).toBeVisible();
  });

  test('can navigate to Trust Center page', async ({ page }) => {
    await page.goto('/trust-center');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Trust/i })).toBeVisible();
  });

  test('can navigate to Settings page', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2').filter({ hasText: /Setting/i })).toBeVisible();
  });
});

test.describe('Smoke Tests - Sidebar Navigation', () => {
  test('sidebar is visible and functional', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Check sidebar exists
    const sidebar = page.locator('nav, aside').first();
    await expect(sidebar).toBeVisible();
    
    // Check key navigation links exist
    const navLinks = ['Dashboard', 'Controls', 'Risks', 'Policies', 'Vendors'];
    for (const link of navLinks) {
      await expect(page.locator(`a, button`).filter({ hasText: new RegExp(link, 'i') }).first()).toBeVisible();
    }
  });

  test('can use sidebar to navigate', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Click on Controls link in sidebar
    await page.click('a[href*="controls"], button:has-text("Controls")');
    await page.waitForLoadState('networkidle');
    
    // Verify navigation worked
    await expect(page).toHaveURL(/controls/);
  });
});

test.describe('Smoke Tests - Responsive Design', () => {
  test('mobile viewport renders correctly', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Page should still be functional
    await expect(page.locator('body')).toBeVisible();
    
    // Check for mobile menu button if sidebar is hidden
    const mobileMenuButton = page.locator('button[aria-label*="menu"], button:has-text("Menu"), [data-testid="mobile-menu"]');
    // Either menu button exists or sidebar is still visible
    const hasMobileMenu = await mobileMenuButton.count() > 0;
    const hasSidebar = await page.locator('nav, aside').first().isVisible();
    expect(hasMobileMenu || hasSidebar).toBeTruthy();
  });

  test('tablet viewport renders correctly', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Page should render without horizontal scroll
    const body = page.locator('body');
    const bodyWidth = await body.evaluate(el => el.scrollWidth);
    expect(bodyWidth).toBeLessThanOrEqual(768);
  });
});




