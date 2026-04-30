import { Logger } from '@nestjs/common';

/**
 * Circuit Breaker States
 */
export enum CircuitState {
  CLOSED = 'CLOSED',     // Normal operation - requests pass through
  OPEN = 'OPEN',         // Circuit tripped - requests fail fast
  HALF_OPEN = 'HALF_OPEN' // Testing if service recovered
}

/**
 * Circuit Breaker Configuration Options
 */
export interface CircuitBreakerOptions {
  /** Name for logging and metrics */
  name: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
  /** Error threshold percentage to trip circuit (default: 50) */
  errorThresholdPercentage?: number;
  /** Time in ms before attempting reset (default: 30000) */
  resetTimeout?: number;
  /** Minimum requests before calculating error percentage (default: 5) */
  volumeThreshold?: number;
  /** Custom function to determine if error should count (default: all errors) */
  isFailure?: (error: Error) => boolean;
  /** Callback when circuit opens */
  onOpen?: () => void;
  /** Callback when circuit closes */
  onClose?: () => void;
  /** Callback when circuit half-opens */
  onHalfOpen?: () => void;
}

/**
 * Circuit Breaker Statistics
 */
export interface CircuitBreakerStats {
  state: CircuitState;
  failures: number;
  successes: number;
  totalRequests: number;
  lastFailureTime?: Date;
  lastSuccessTime?: Date;
}

/**
 * Circuit Breaker Error - thrown when circuit is open
 */
export class CircuitBreakerOpenError extends Error {
  constructor(name: string) {
    super(`Circuit breaker '${name}' is OPEN - failing fast`);
    this.name = 'CircuitBreakerOpenError';
  }
}

/**
 * Circuit Breaker Error - thrown when request times out
 */
export class CircuitBreakerTimeoutError extends Error {
  constructor(name: string, timeout: number) {
    super(`Circuit breaker '${name}' request timed out after ${timeout}ms`);
    this.name = 'CircuitBreakerTimeoutError';
  }
}

/**
 * Circuit Breaker implementation for protecting external service calls.
 * 
 * The circuit breaker pattern prevents cascade failures by:
 * - Monitoring failure rates of external calls
 * - Opening the circuit (failing fast) when error threshold is exceeded
 * - Periodically testing if the service has recovered
 * - Closing the circuit when service is healthy again
 * 
 * @example
 * ```typescript
 * const breaker = new CircuitBreaker({
 *   name: 'external-api',
 *   timeout: 5000,
 *   errorThresholdPercentage: 50,
 *   resetTimeout: 30000,
 * });
 * 
 * const result = await breaker.fire(() => fetch('https://api.example.com/data'));
 * ```
 */
export class CircuitBreaker<T = unknown> {
  private readonly logger = new Logger('CircuitBreaker');
  private state: CircuitState = CircuitState.CLOSED;
  private failures = 0;
  private successes = 0;
  private lastFailureTime?: Date;
  private lastSuccessTime?: Date;
  private resetTimer?: NodeJS.Timeout;

  private readonly name: string;
  private readonly timeout: number;
  private readonly errorThresholdPercentage: number;
  private readonly resetTimeout: number;
  private readonly volumeThreshold: number;
  private readonly isFailure: (error: Error) => boolean;
  private readonly onOpen?: () => void;
  private readonly onClose?: () => void;
  private readonly onHalfOpen?: () => void;

  constructor(options: CircuitBreakerOptions) {
    this.name = options.name;
    this.timeout = options.timeout ?? 10000;
    this.errorThresholdPercentage = options.errorThresholdPercentage ?? 50;
    this.resetTimeout = options.resetTimeout ?? 30000;
    this.volumeThreshold = options.volumeThreshold ?? 5;
    this.isFailure = options.isFailure ?? (() => true);
    this.onOpen = options.onOpen;
    this.onClose = options.onClose;
    this.onHalfOpen = options.onHalfOpen;
  }

  /**
   * Execute a function through the circuit breaker
   */
  async fire(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      throw new CircuitBreakerOpenError(this.name);
    }

    try {
      const result = await this.executeWithTimeout(fn);
      this.onSuccess();
      return result;
    } catch (error) {
      if (this.isFailure(error as Error)) {
        this.onFailure();
      }
      throw error;
    }
  }

  /**
   * Execute function with timeout protection
   */
  private async executeWithTimeout(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new CircuitBreakerTimeoutError(this.name, this.timeout));
      }, this.timeout);

      fn()
        .then((result) => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(error);
        });
    });
  }

  /**
   * Handle successful request
   */
  private onSuccess(): void {
    this.successes++;
    this.lastSuccessTime = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.close();
    }
  }

  /**
   * Handle failed request
   */
  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.open();
      return;
    }

    if (this.shouldTrip()) {
      this.open();
    }
  }

  /**
   * Check if circuit should trip open
   */
  private shouldTrip(): boolean {
    const total = this.failures + this.successes;
    if (total < this.volumeThreshold) {
      return false;
    }

    const errorPercentage = (this.failures / total) * 100;
    return errorPercentage >= this.errorThresholdPercentage;
  }

  /**
   * Open the circuit (fail fast mode)
   */
  private open(): void {
    if (this.state === CircuitState.OPEN) return;

    this.state = CircuitState.OPEN;
    this.logger.warn(`Circuit breaker '${this.name}' OPENED - failing fast`);
    this.onOpen?.();

    // Schedule half-open transition
    this.resetTimer = setTimeout(() => {
      this.halfOpen();
    }, this.resetTimeout);
  }

  /**
   * Half-open the circuit (testing mode)
   */
  private halfOpen(): void {
    this.state = CircuitState.HALF_OPEN;
    this.logger.log(`Circuit breaker '${this.name}' HALF-OPEN - testing recovery`);
    this.onHalfOpen?.();
  }

  /**
   * Close the circuit (normal operation)
   */
  private close(): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = undefined;
    }

    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.logger.log(`Circuit breaker '${this.name}' CLOSED - normal operation`);
    this.onClose?.();
  }

  /**
   * Get current circuit breaker statistics
   */
  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      totalRequests: this.failures + this.successes,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
    };
  }

  /**
   * Get current circuit state
   */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Check if circuit is allowing requests
   */
  isAllowingRequests(): boolean {
    return this.state !== CircuitState.OPEN;
  }

  /**
   * Force reset the circuit breaker (for testing/admin)
   */
  reset(): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = undefined;
    }
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = undefined;
    this.lastSuccessTime = undefined;
    this.logger.log(`Circuit breaker '${this.name}' manually reset`);
  }
}

/**
 * Factory function to create a circuit breaker with sensible defaults
 */
export function createCircuitBreaker<T = unknown>(
  name: string,
  options?: Partial<Omit<CircuitBreakerOptions, 'name'>>
): CircuitBreaker<T> {
  return new CircuitBreaker<T>({
    name,
    ...options,
  });
}

/**
 * Registry to manage multiple circuit breakers
 */
export class CircuitBreakerRegistry {
  private readonly breakers = new Map<string, CircuitBreaker>();

  /**
   * Get or create a circuit breaker by name
   */
  getOrCreate<T = unknown>(
    name: string,
    options?: Partial<Omit<CircuitBreakerOptions, 'name'>>
  ): CircuitBreaker<T> {
    if (!this.breakers.has(name)) {
      this.breakers.set(name, createCircuitBreaker<T>(name, options));
    }
    return this.breakers.get(name) as CircuitBreaker<T>;
  }

  /**
   * Get all circuit breaker statistics
   */
  getAllStats(): Record<string, CircuitBreakerStats> {
    const stats: Record<string, CircuitBreakerStats> = {};
    for (const [name, breaker] of this.breakers) {
      stats[name] = breaker.getStats();
    }
    return stats;
  }

  /**
   * Reset all circuit breakers
   */
  resetAll(): void {
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }
  }
}

// Global registry instance
export const circuitBreakerRegistry = new CircuitBreakerRegistry();
