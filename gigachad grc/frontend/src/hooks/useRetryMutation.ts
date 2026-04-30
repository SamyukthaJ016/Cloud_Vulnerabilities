import { useState, useCallback } from 'react';
import { useMutation, UseMutationOptions, UseMutationResult } from '@tanstack/react-query';

interface RetryState {
  attempts: number;
  lastError: Error | null;
  isRetrying: boolean;
}

interface UseRetryMutationOptions<TData, TError, TVariables, TContext>
  extends Omit<UseMutationOptions<TData, TError, TVariables, TContext>, 'retry'> {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay between retries in ms (default: 1000) */
  retryDelay?: number;
  /** Whether to use exponential backoff (default: true) */
  exponentialBackoff?: boolean;
  /** Errors that should not be retried (e.g., validation errors) */
  nonRetryableStatuses?: number[];
}

/**
 * Enhanced mutation hook with manual retry capability
 * Provides retry state and manual retry function for better UX
 */
export function useRetryMutation<
  TData = unknown,
  TError = Error,
  TVariables = void,
  TContext = unknown
>(
  options: UseRetryMutationOptions<TData, TError, TVariables, TContext>
): UseMutationResult<TData, TError, TVariables, TContext> & {
  retryState: RetryState;
  manualRetry: () => void;
  resetRetryState: () => void;
} {
  const {
    maxRetries = 3,
    retryDelay = 1000,
    exponentialBackoff = true,
    nonRetryableStatuses = [400, 401, 403, 404, 422],
    onError,
    ...mutationOptions
  } = options;

  const [retryState, setRetryState] = useState<RetryState>({
    attempts: 0,
    lastError: null,
    isRetrying: false,
  });

  const [lastVariables, setLastVariables] = useState<TVariables | null>(null);

  const isRetryableError = useCallback((error: TError): boolean => {
    if (error && typeof error === 'object' && 'response' in error) {
      const status = (error as any).response?.status;
      if (status && nonRetryableStatuses.includes(status)) {
        return false;
      }
    }
    return true;
  }, [nonRetryableStatuses]);

  const mutation = useMutation<TData, TError, TVariables, TContext>({
    ...mutationOptions,
    onError: (error, variables, context) => {
      setRetryState(prev => ({
        ...prev,
        lastError: error instanceof Error ? error : new Error(String(error)),
      }));
      setLastVariables(variables);
      // React Query's onError receives four arguments; pass a fourth placeholder to satisfy types
      onError?.(error, variables, context, null as any);
    },
    onSuccess: (data, variables, context) => {
      // Reset retry state on success
      setRetryState({
        attempts: 0,
        lastError: null,
        isRetrying: false,
      });
      // React Query's onSuccess can receive four arguments; pass a fourth placeholder to satisfy types
      mutationOptions.onSuccess?.(data, variables, context, null as any);
    },
  });

  const manualRetry = useCallback(async () => {
    if (!lastVariables || !retryState.lastError) return;
    if (!isRetryableError(retryState.lastError as unknown as TError)) return;
    if (retryState.attempts >= maxRetries) return;

    const attemptNumber = retryState.attempts + 1;
    const delay = exponentialBackoff
      ? retryDelay * Math.pow(2, retryState.attempts)
      : retryDelay;

    setRetryState(prev => ({
      ...prev,
      attempts: attemptNumber,
      isRetrying: true,
    }));

    // Wait before retrying
    await new Promise(resolve => setTimeout(resolve, delay));

    try {
      await mutation.mutateAsync(lastVariables);
      setRetryState({
        attempts: 0,
        lastError: null,
        isRetrying: false,
      });
    } catch {
      setRetryState(prev => ({
        ...prev,
        isRetrying: false,
      }));
    }
  }, [lastVariables, retryState, maxRetries, exponentialBackoff, retryDelay, mutation, isRetryableError]);

  const resetRetryState = useCallback(() => {
    setRetryState({
      attempts: 0,
      lastError: null,
      isRetrying: false,
    });
    setLastVariables(null);
  }, []);

  return {
    ...mutation,
    retryState,
    manualRetry,
    resetRetryState,
  };
}

export default useRetryMutation;

