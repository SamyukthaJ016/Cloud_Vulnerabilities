import { QueryClient } from '@tanstack/react-query';

/**
 * Global TanStack Query config.
 *   - staleTime 30s: most dashboard data refreshes on WS events, not polling
 *   - retry once on non-4xx; 4xx (bad request, auth, forbidden) should not retry
 *   - throwOnError for 401 so the HTTP interceptor can redirect to /login
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        const status = (error as { status?: number } | null)?.status;
        if (status && status >= 400 && status < 500) return false;
        return failureCount < 1;
      },
    },
    mutations: {
      retry: false,
    },
  },
});
