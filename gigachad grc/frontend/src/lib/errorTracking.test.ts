import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  errorTracking,
  captureError,
  captureMessage,
  setUserForErrorTracking,
  clearUserForErrorTracking,
} from './errorTracking';

describe('Error Tracking Library', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('captureError', () => {
    it('logs errors to console', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const error = new Error('Test error');
      
      captureError(error);
      
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('logs errors with context to console', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const error = new Error('Test error');
      const context = { userId: 'user-123', organizationId: 'org-456' };
      
      captureError(error, context);
      
      expect(consoleSpy).toHaveBeenCalledWith('[Error]', error, context);
      consoleSpy.mockRestore();
    });

    it('handles non-Error objects', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      captureError('String error');
      captureError({ message: 'Object error' });
      captureError(undefined);
      
      expect(consoleSpy).toHaveBeenCalledTimes(3);
      consoleSpy.mockRestore();
    });
  });

  describe('captureMessage', () => {
    it('logs info messages to console', () => {
      const consoleSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
      
      captureMessage('Test message', 'info');
      
      expect(consoleSpy).toHaveBeenCalledWith('[INFO]', 'Test message', undefined);
      consoleSpy.mockRestore();
    });

    it('logs warning messages to console', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      captureMessage('Test warning', 'warning');
      
      expect(consoleSpy).toHaveBeenCalledWith('[WARNING]', 'Test warning', undefined);
      consoleSpy.mockRestore();
    });

    it('logs error messages to console', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      captureMessage('Test error message', 'error');
      
      expect(consoleSpy).toHaveBeenCalledWith('[ERROR]', 'Test error message', undefined);
      consoleSpy.mockRestore();
    });

    it('includes extra data in log', () => {
      const consoleSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
      const extra = { component: 'TestComponent', action: 'click' };
      
      captureMessage('Test message', 'info', extra);
      
      expect(consoleSpy).toHaveBeenCalledWith('[INFO]', 'Test message', extra);
      consoleSpy.mockRestore();
    });
  });

  describe('setUserForErrorTracking', () => {
    it('does not throw when setting user', () => {
      expect(() => {
        setUserForErrorTracking({
          id: 'user-123',
          email: 'test@example.com',
          name: 'Test User',
          organizationId: 'org-456',
        });
      }).not.toThrow();
    });

    it('does not throw when setting null user', () => {
      expect(() => {
        setUserForErrorTracking(null);
      }).not.toThrow();
    });
  });

  describe('clearUserForErrorTracking', () => {
    it('does not throw when clearing user', () => {
      expect(() => {
        clearUserForErrorTracking();
      }).not.toThrow();
    });
  });

  describe('errorTracking service', () => {
    it('reports Sentry as not available when not installed', () => {
      // Without @sentry/react installed, this should return false
      expect(errorTracking.isSentryAvailable()).toBe(false);
    });
  });
});
