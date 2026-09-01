import { describe, it, expect, vi, beforeEach } from 'vitest';
import { extractErrorMessage } from './useToast';

// Mock react-hot-toast
vi.mock('react-hot-toast', () => ({
  default: {
    success: vi.fn(),
    error: vi.fn(),
    loading: vi.fn(),
    dismiss: vi.fn(),
    promise: vi.fn(),
  },
}));

describe('useToast', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('extractErrorMessage', () => {
    it('extracts message from Axios error response', () => {
      const error = {
        isAxiosError: true,
        response: {
          data: {
            message: 'Validation failed',
          },
        },
      };
      expect(extractErrorMessage(error)).toBe('Validation failed');
    });

    it('extracts message array from Axios error response', () => {
      const error = {
        isAxiosError: true,
        response: {
          data: {
            message: ['Field is required', 'Invalid format'],
          },
        },
      };
      expect(extractErrorMessage(error)).toBe('Field is required, Invalid format');
    });

    it('extracts error from Axios error response', () => {
      const error = {
        isAxiosError: true,
        response: {
          data: {
            error: 'Not found',
          },
        },
      };
      expect(extractErrorMessage(error)).toBe('Not found');
    });

    it('extracts message from Error object', () => {
      const error = new Error('Something went wrong');
      expect(extractErrorMessage(error)).toBe('Something went wrong');
    });

    it('returns string error as-is', () => {
      const error = 'Simple error message';
      expect(extractErrorMessage(error)).toBe('Simple error message');
    });

    it('returns fallback for unknown error types', () => {
      const error = { unknown: 'structure' };
      expect(extractErrorMessage(error)).toBe('An unexpected error occurred. Please try again.');
    });

    it('returns fallback for null error', () => {
      expect(extractErrorMessage(null)).toBe('An unexpected error occurred. Please try again.');
    });

    it('returns fallback for undefined error', () => {
      expect(extractErrorMessage(undefined)).toBe('An unexpected error occurred. Please try again.');
    });
  });
});
