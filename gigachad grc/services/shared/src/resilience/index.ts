/**
 * Resilience Module
 * 
 * Provides patterns and utilities for building resilient services:
 * - Circuit Breaker: Prevents cascade failures when external services are down
 * - Retry with Backoff: Handles transient failures gracefully
 * 
 * @module resilience
 */

export {
  // Circuit Breaker
  CircuitBreaker,
  CircuitBreakerRegistry,
  CircuitState,
  CircuitBreakerOpenError,
  CircuitBreakerTimeoutError,
  createCircuitBreaker,
  circuitBreakerRegistry,
  type CircuitBreakerOptions,
  type CircuitBreakerStats,
} from './circuit-breaker';

export {
  // Retry
  withRetry,
  withRetryResult,
  createRetryable,
  Retryable,
  RetryPolicies,
  type RetryOptions,
  type RetryResult,
} from './retry';
