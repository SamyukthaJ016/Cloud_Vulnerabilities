import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';

interface ApiHealthState {
  isHealthy: boolean;
  lastChecked: Date | null;
  consecutiveFailures: number;
  isChecking: boolean;
}

interface UseApiHealthOptions {
  /** Health check endpoint (default: /api/health) */
  endpoint?: string;
  /** Check interval in ms (default: 30000 = 30 seconds) */
  checkInterval?: number;
  /** Number of failures before marking as unhealthy (default: 3) */
  failureThreshold?: number;
  /** Callback when API becomes unhealthy */
  onUnhealthy?: () => void;
  /** Callback when API recovers */
  onRecovery?: () => void;
  /** Whether to run health checks (default: true) */
  enabled?: boolean;
}

/**
 * Hook to monitor API health and detect connectivity issues
 * Useful for showing connection status and triggering reconnection logic
 */
export function useApiHealth({
  endpoint = '/api/health',
  checkInterval = 30000,
  failureThreshold = 3,
  onUnhealthy,
  onRecovery,
  enabled = true,
}: UseApiHealthOptions = {}) {
  const [state, setState] = useState<ApiHealthState>({
    isHealthy: true,
    lastChecked: null,
    consecutiveFailures: 0,
    isChecking: false,
  });

  const wasHealthy = useRef(true);

  const checkHealth = useCallback(async () => {
    if (!enabled) return;

    setState(prev => ({ ...prev, isChecking: true }));

    try {
      await axios.get(endpoint, {
        timeout: 5000,
        // Skip interceptors for health checks
        headers: { 'X-Skip-Auth': 'true' },
      });

      setState(() => {
        const newState = {
          isHealthy: true,
          lastChecked: new Date(),
          consecutiveFailures: 0,
          isChecking: false,
        };

        // Fire recovery callback if we were unhealthy
        if (!wasHealthy.current) {
          wasHealthy.current = true;
          onRecovery?.();
        }

        return newState;
      });
    } catch {
      setState(prev => {
        const newFailures = prev.consecutiveFailures + 1;
        const nowUnhealthy = newFailures >= failureThreshold;

        // Fire unhealthy callback if we just became unhealthy
        if (nowUnhealthy && wasHealthy.current) {
          wasHealthy.current = false;
          onUnhealthy?.();
        }

        return {
          isHealthy: !nowUnhealthy,
          lastChecked: new Date(),
          consecutiveFailures: newFailures,
          isChecking: false,
        };
      });
    }
  }, [endpoint, enabled, failureThreshold, onUnhealthy, onRecovery]);

  // Initial check and periodic checks
  useEffect(() => {
    if (!enabled) return;

    checkHealth();
    const interval = setInterval(checkHealth, checkInterval);

    return () => clearInterval(interval);
  }, [checkHealth, checkInterval, enabled]);

  // Check on window focus (user returning to tab)
  useEffect(() => {
    if (!enabled) return;

    const handleFocus = () => {
      // Only check if it's been more than 10 seconds since last check
      if (
        state.lastChecked &&
        Date.now() - state.lastChecked.getTime() > 10000
      ) {
        checkHealth();
      }
    };

    window.addEventListener('focus', handleFocus);
    return () => window.removeEventListener('focus', handleFocus);
  }, [enabled, state.lastChecked, checkHealth]);

  return {
    ...state,
    checkNow: checkHealth,
  };
}

export default useApiHealth;

