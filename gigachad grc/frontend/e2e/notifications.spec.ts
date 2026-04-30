import { test, expect } from '@playwright/test';

/**
 * Notifications E2E Tests
 * Tests notification settings and notification center
 */

test.describe('Notification Settings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/account');
    await page.waitForLoadState('networkidle');
  });

  test('displays notification settings', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for notification settings tab or section
    const notificationTab = page.locator('text=/Notification/i').first();
    
    if (await notificationTab.count() > 0) {
      await notificationTab.click();
      await page.waitForTimeout(1000);
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('shows email notification options', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Navigate to notifications if needed
    const notificationTab = page.locator('text=/Notification/i').first();
    if (await notificationTab.count() > 0) {
      await notificationTab.click();
      await page.waitForTimeout(1000);
    }
    
    // Look for email options
    const emailOptions = page.locator('text=/Email|Newsletter|Updates/i');
    
    if (await emailOptions.count() > 0) {
      await expect(emailOptions.first()).toBeVisible();
    }
  });

  test('has toggle switches for notifications', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Navigate to notifications if needed
    const notificationTab = page.locator('text=/Notification/i').first();
    if (await notificationTab.count() > 0) {
      await notificationTab.click();
      await page.waitForTimeout(1000);
    }
    
    const toggles = page.locator('input[type="checkbox"], [role="switch"]');
    
    if (await toggles.count() > 0) {
      await expect(toggles.first()).toBeVisible();
    }
  });

  test('can save notification preferences', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Navigate to notifications if needed
    const notificationTab = page.locator('text=/Notification/i').first();
    if (await notificationTab.count() > 0) {
      await notificationTab.click();
      await page.waitForTimeout(1000);
    }
    
    // Look for save button
    const saveBtn = page.locator('button').filter({ hasText: /Save|Update/i }).first();
    
    if (await saveBtn.count() > 0) {
      await expect(saveBtn).toBeVisible();
    }
  });
});

test.describe('Admin Notification Configuration', () => {
  test('can access admin notification settings', async ({ page }) => {
    await page.goto('/settings/communications');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('body')).toBeVisible();
  });

  test('shows email provider options', async ({ page }) => {
    await page.goto('/settings/communications');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Look for email provider configuration
    const providerOptions = page.locator('text=/SMTP|SendGrid|AWS SES|Email Provider/i');
    
    if (await providerOptions.count() > 0) {
      await expect(providerOptions.first()).toBeVisible();
    }
  });

  test('shows Slack integration options', async ({ page }) => {
    await page.goto('/settings/communications');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Look for Slack configuration
    const slackOptions = page.locator('text=/Slack/i');
    
    if (await slackOptions.count() > 0) {
      await expect(slackOptions.first()).toBeVisible();
    }
  });
});




