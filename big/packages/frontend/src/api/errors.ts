import { toast } from 'sonner';
import { useCallback } from 'react';

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/**
 * Hook that returns a `toastError(err)` helper. Every mutation's onError
 * should call it unless the feature has a custom error display.
 */
export function useApiErrorToast() {
  return useCallback((err: unknown, fallback = 'Something went wrong') => {
    const message = isApiError(err) ? err.message : fallback;
    toast.error(message);
  }, []);
}
