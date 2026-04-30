import { Logger } from '@nestjs/common';

const logger = new Logger('Retry');

/**
 * Retry Configuration Options
 */
export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay in milliseconds for exponential backoff (default: 1000) */
  baseDelayMs?: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs?: number;
  /** Jitter factor 0-1 to add randomness to delays (default: 0.1) */
  jitter?: number;
  /** Custom function to determine if error is retryable */
  isRetryable?: (error: Error, attempt: number) => boolean;
  /** Callback called before each retry attempt */
  onRetry?: (error: Error, attempt: number, delay: number) => void;
  /** Operation name for logging */
  operationName?: string;
}

/**
 * Retry Result with metadata
 */
export interface RetryResult<T> {
  success: boolean;
  result?: T;
  error?: Error;
  attempts: number;
  totalTimeMs: number;
}

/**
 * Default function to determine if an error is retryable
 */
function defaultIsRetryable(error: Error): boolean {
  // Retry on network errors
  if (error.message.includes('ECONNREFUSED') ||
      error.message.includes('ECONNRESET') ||
      error.message.includes('ETIMEDOUT') ||
      error.message.includes('ENOTFOUND') ||
      error.message.includes('EAI_AGAIN') ||
      error.message.includes('socket hang up') ||
      error.message.includes('network')) {
    return true;
  }

  // Retry on specific HTTP status codes (if available)
  const statusMatch = error.message.match(/status[:\s]*(\d{3})/i);
  if (statusMatch) {
    const status = parseInt(statusMatch[1], 10);
    // Retry on 429 (Too Many Requests), 502, 503, 504 (Server Errors)
    if ([429, 502, 503, 504].includes(status)) {
      return true;
    }
  }

  // Check for common transient error names
  const retryableNames = [
    'TimeoutError',
    'NetworkError',
    'FetchError',
    'AbortError',
    'CircuitBreakerTimeoutError',
  ];
  if (retryableNames.includes(error.name)) {
    return true;
  }

  return false;
}

/**
 * Calculate delay with exponential backoff and jitter
 */
function calculateDelay(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number,
  jitter: number
): number {
  // Exponential backoff: base * 2^attempt
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt);
  
  // Cap at maximum delay
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);
  
  // Add jitter (random factor to prevent thundering herd)
  const jitterAmount = cappedDelay * jitter * Math.random();
  
  return Math.floor(cappedDelay + jitterAmount);
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute a function with retry logic and exponential backoff.
 * 
 * @example
 * ```typescript
 * // Simple usage
 * const result = await withRetry(() => fetchExternalAPI());
 * 
 * // With options
 * const result = await withRetry(
 *   () => fetchExternalAPI(),
 *   {
 *     maxRetries: 5,
 *     baseDelayMs: 2000,
 *     operationName: 'fetch-external-api',
 *     onRetry: (err, attempt) => console.log(`Retry ${attempt}...`),
 *   }
 * );
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: RetryOptions
): Promise<T> {
  const maxRetries = options?.maxRetries ?? 3;
  const baseDelayMs = options?.baseDelayMs ?? 1000;
  const maxDelayMs = options?.maxDelayMs ?? 30000;
  const jitter = options?.jitter ?? 0.1;
  const isRetryable = options?.isRetryable ?? defaultIsRetryable;
  const operationName = options?.operationName ?? 'operation';

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Check if we've exhausted retries
      if (attempt === maxRetries) {
        logger.error(
          `${operationName}: All ${maxRetries + 1} attempts failed. Last error: ${lastError.message}`
        );
        throw lastError;
      }

      // Check if error is retryable
      if (!isRetryable(lastError, attempt)) {
        logger.warn(
          `${operationName}: Non-retryable error on attempt ${attempt + 1}: ${lastError.message}`
        );
        throw lastError;
      }

      // Calculate delay for next attempt
      const delay = calculateDelay(attempt, baseDelayMs, maxDelayMs, jitter);

      logger.warn(
        `${operationName}: Attempt ${attempt + 1} failed: ${lastError.message}. ` +
        `Retrying in ${delay}ms (${maxRetries - attempt} retries left)`
      );

      // Call onRetry callback if provided
      options?.onRetry?.(lastError, attempt + 1, delay);

      // Wait before next attempt
      await sleep(delay);
    }
  }

  // Should never reach here, but TypeScript needs this
  throw lastError ?? new Error('Retry exhausted with no error');
}

/**
 * Execute a function with retry logic and return detailed result.
 * Unlike withRetry, this doesn't throw on failure.
 * 
 * @example
 * ```typescript
 * const result = await withRetryResult(() => fetchExternalAPI());
 * if (result.success) {
 *   console.log('Data:', result.result);
 * } else {
 *   console.log('Failed after', result.attempts, 'attempts:', result.error);
 * }
 * ```
 */
export async function withRetryResult<T>(
  fn: () => Promise<T>,
  options?: RetryOptions
): Promise<RetryResult<T>> {
  const startTime = Date.now();
  let attempts = 0;

  const trackingOptions: RetryOptions = {
    ...options,
    onRetry: (error, attempt, delay) => {
      attempts = attempt;
      options?.onRetry?.(error, attempt, delay);
    },
  };

  try {
    const result = await withRetry(fn, trackingOptions);
    return {
      success: true,
      result,
      attempts: attempts + 1,
      totalTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      success: false,
      error: error as Error,
      attempts: (options?.maxRetries ?? 3) + 1,
      totalTimeMs: Date.now() - startTime,
    };
  }
}

/**
 * Create a retryable version of a function.
 * Useful for wrapping functions that should always have retry logic.
 * 
 * @example
 * ```typescript
 * const retryableFetch = createRetryable(
 *   (url: string) => fetch(url).then(r => r.json()),
 *   { maxRetries: 3, operationName: 'http-fetch' }
 * );
 * 
 * const data = await retryableFetch('https://api.example.com/data');
 * ```
 */
export function createRetryable<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
  options?: RetryOptions
): (...args: TArgs) => Promise<TResult> {
  return (...args: TArgs) => withRetry(() => fn(...args), options);
}

/**
 * Decorator factory for adding retry logic to async methods.
 * 
 * @example
 * ```typescript
 * class ApiService {
 *   @Retryable({ maxRetries: 3, operationName: 'fetch-users' })
 *   async fetchUsers(): Promise<User[]> {
 *     return this.httpClient.get('/users');
 *   }
 * }
 * ```
 */
export function Retryable(options?: RetryOptions): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      const operationName = options?.operationName ?? 
        `${target.constructor.name}.${String(propertyKey)}`;
      
      return withRetry(
        () => originalMethod.apply(this, args),
        { ...options, operationName }
      );
    };

    return descriptor;
  };
}

/**
 * Retry policies for common scenarios
 */
export const RetryPolicies = {
  /** Quick retry for local services (3 retries, 500ms base delay) */
  fast: {
    maxRetries: 3,
    baseDelayMs: 500,
    maxDelayMs: 5000,
    jitter: 0.1,
  } as RetryOptions,

  /** Standard retry for external APIs (3 retries, 1s base delay) */
  standard: {
    maxRetries: 3,
    baseDelayMs: 1000,
    maxDelayMs: 30000,
    jitter: 0.2,
  } as RetryOptions,

  /** Aggressive retry for critical operations (5 retries, 2s base delay) */
  aggressive: {
    maxRetries: 5,
    baseDelayMs: 2000,
    maxDelayMs: 60000,
    jitter: 0.3,
  } as RetryOptions,

  /** Database connection retry (10 retries, 1s base delay) */
  database: {
    maxRetries: 10,
    baseDelayMs: 1000,
    maxDelayMs: 30000,
    jitter: 0.1,
  } as RetryOptions,

  /** No retry - just wraps for consistency */
  none: {
    maxRetries: 0,
  } as RetryOptions,
};
