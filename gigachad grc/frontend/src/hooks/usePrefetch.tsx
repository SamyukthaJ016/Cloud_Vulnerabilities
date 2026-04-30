import { useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  controlsApi,
  risksApi,
  frameworksApi,
  policiesApi,
  evidenceApi,
  vendorsApi,
  dashboardApi,
} from '@/lib/api';

/**
 * Hook for prefetching data on navigation hover
 * Improves perceived performance by loading data before navigation
 */
export function usePrefetch() {
  const queryClient = useQueryClient();

  // Prefetch control detail
  const prefetchControl = useCallback(
    (controlId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['control', controlId],
        queryFn: () => controlsApi.get(controlId).then((res) => res.data),
        staleTime: 60 * 1000, // 1 minute
      });
    },
    [queryClient]
  );

  // Prefetch risk detail
  const prefetchRisk = useCallback(
    (riskId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['risk', riskId],
        queryFn: () => risksApi.get(riskId).then((res) => res.data),
        staleTime: 60 * 1000,
      });
    },
    [queryClient]
  );

  // Prefetch framework detail
  const prefetchFramework = useCallback(
    (frameworkId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['framework', frameworkId],
        queryFn: () => frameworksApi.get(frameworkId).then((res) => res.data),
        staleTime: 5 * 60 * 1000, // 5 minutes - frameworks change less often
      });
    },
    [queryClient]
  );

  // Prefetch policy detail
  const prefetchPolicy = useCallback(
    (policyId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['policy', policyId],
        queryFn: () => policiesApi.get(policyId).then((res) => res.data),
        staleTime: 60 * 1000,
      });
    },
    [queryClient]
  );

  // Prefetch evidence detail
  const prefetchEvidence = useCallback(
    (evidenceId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['evidence', evidenceId],
        queryFn: () => evidenceApi.get(evidenceId).then((res) => res.data),
        staleTime: 60 * 1000,
      });
    },
    [queryClient]
  );

  // Prefetch vendor detail
  const prefetchVendor = useCallback(
    (vendorId: string) => {
      queryClient.prefetchQuery({
        queryKey: ['vendor', vendorId],
        queryFn: () => vendorsApi.get(vendorId).then((res) => res.data),
        staleTime: 60 * 1000,
      });
    },
    [queryClient]
  );

  // Prefetch list pages (for navigation links)
  const prefetchControlsList = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['controls', '', '', '', ''],
      queryFn: () => controlsApi.list({ limit: 25 }).then((res) => res.data),
      staleTime: 30 * 1000,
    });
  }, [queryClient]);

  const prefetchRisksList = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['risks', {}, null],
      queryFn: () => risksApi.list({ limit: 25 }).then((res) => res.data),
      staleTime: 30 * 1000,
    });
  }, [queryClient]);

  const prefetchDashboard = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['dashboard-summary'],
      queryFn: () => dashboardApi.getSummary().then((res) => res.data),
      staleTime: 60 * 1000,
    });
  }, [queryClient]);

  const prefetchFrameworks = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['frameworks'],
      queryFn: () => frameworksApi.list().then((res) => res.data),
      staleTime: 5 * 60 * 1000,
    });
  }, [queryClient]);

  const prefetchPolicies = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['policies'],
      queryFn: () => policiesApi.list({ limit: 25 }).then((res) => res.data),
      staleTime: 30 * 1000,
    });
  }, [queryClient]);

  const prefetchVendors = useCallback(() => {
    queryClient.prefetchQuery({
      queryKey: ['vendors', ''],
      queryFn: () => vendorsApi.list({ limit: 25 }).then((res) => res.data),
      staleTime: 30 * 1000,
    });
  }, [queryClient]);

  return {
    // Detail prefetchers
    prefetchControl,
    prefetchRisk,
    prefetchFramework,
    prefetchPolicy,
    prefetchEvidence,
    prefetchVendor,
    // List prefetchers
    prefetchControlsList,
    prefetchRisksList,
    prefetchDashboard,
    prefetchFrameworks,
    prefetchPolicies,
    prefetchVendors,
  };
}

/**
 * Helper component to prefetch on hover/focus
 */
export function PrefetchLink({
  children,
  onPrefetch,
  className,
}: {
  children: React.ReactNode;
  onPrefetch: () => void;
  className?: string;
}) {
  return (
    <div
      onMouseEnter={onPrefetch}
      onFocus={onPrefetch}
      className={className}
    >
      {children}
    </div>
  );
}

export default usePrefetch;

