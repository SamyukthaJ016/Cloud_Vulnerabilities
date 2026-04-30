import { useState, useEffect, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  getOnlineStatus,
  onOnlineStatusChange,
  queueAction,
  getPendingActions,
  syncPendingActions,
  cacheData,
  getCachedData,
  getStorageStats,
} from '@/lib/offlineSync';
import toast from 'react-hot-toast';

interface PendingAction {
  id: string;
  type: 'create' | 'update' | 'delete';
  entity: string;
  data: unknown;
  timestamp: number;
  retryCount: number;
}

interface StorageStats {
  pendingActions: number;
  cachedItems: number;
  estimatedSize: string;
}

/**
 * Hook for offline-aware operations
 */
export function useOffline() {
  const [isOnline, setIsOnline] = useState(getOnlineStatus());
  const [isSyncing, setIsSyncing] = useState(false);
  const [pendingActions, setPendingActions] = useState<PendingAction[]>([]);
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const queryClient = useQueryClient();

  // Listen for online/offline changes
  useEffect(() => {
    const unsubscribe = onOnlineStatusChange((online) => {
      setIsOnline(online);
      
      if (online) {
        toast.success('Back online! Syncing pending changes...', {
          icon: '🌐',
          duration: 3000,
        });
        handleSync();
      } else {
        toast('You\'re offline. Changes will be saved locally.', {
          icon: '📴',
          duration: 4000,
        });
      }
    });

    return unsubscribe;
  }, []);

  // Load pending actions on mount
  useEffect(() => {
    loadPendingActions();
    loadStorageStats();
  }, []);

  const loadPendingActions = useCallback(() => {
    try {
      const actions = getPendingActions();
      setPendingActions(actions);
    } catch (error) {
      console.error('Failed to load pending actions:', error);
    }
  }, []);

  const loadStorageStats = useCallback(() => {
    try {
      const stats = getStorageStats();
      setStorageStats(stats);
    } catch (error) {
      console.error('Failed to load storage stats:', error);
    }
  }, []);

  // Queue an action for offline sync
  const queueOfflineAction = useCallback(
    (type: 'create' | 'update' | 'delete', entity: string, data: unknown) => {
      try {
        queueAction(type, entity, data);
        loadPendingActions();
        
        if (!isOnline) {
          toast.success('Change saved locally', {
            icon: '💾',
            duration: 2000,
          });
        }
      } catch (error) {
        console.error('Failed to queue action:', error);
        toast.error('Failed to save change');
      }
    },
    [isOnline, loadPendingActions]
  );

  // Manual sync trigger
  const handleSync = useCallback(async () => {
    if (!isOnline || isSyncing) return;

    setIsSyncing(true);
    
    try {
      const result = await syncPendingActions();
      loadPendingActions();
      loadStorageStats();
      
      // Invalidate queries to refresh data
      queryClient.invalidateQueries();
      
      if (result.synced > 0) {
        toast.success(`Synced ${result.synced} changes`, {
          icon: '✅',
        });
      }
      
      if (result.failed > 0) {
        toast.error(`${result.failed} changes failed to sync`);
      }
    } catch (error) {
      console.error('Sync failed:', error);
      toast.error('Sync failed');
    } finally {
      setIsSyncing(false);
    }
  }, [isOnline, isSyncing, queryClient, loadPendingActions, loadStorageStats]);

  // Cache data for offline use
  const cacheForOffline = useCallback(
    (key: string, data: unknown, ttl?: number) => {
      try {
        cacheData(key, data, ttl);
      } catch (error) {
        console.error('Failed to cache data:', error);
      }
    },
    []
  );

  // Get cached data
  const getFromCache = useCallback(<T>(key: string): T | null => {
    try {
      return getCachedData<T>(key);
    } catch (error) {
      console.error('Failed to get cached data:', error);
      return null;
    }
  }, []);

  return {
    isOnline,
    isSyncing,
    pendingActions,
    pendingCount: pendingActions.length,
    storageStats,
    queueOfflineAction,
    sync: handleSync,
    cacheForOffline,
    getFromCache,
    refreshStats: loadStorageStats,
  };
}

/**
 * Hook for offline-aware API calls
 */
export function useOfflineQuery<T>(
  key: string,
  queryFn: () => Promise<T>,
  options?: {
    cacheKey?: string;
    cacheTtl?: number;
    fallbackData?: T;
  }
) {
  const { isOnline, cacheForOffline, getFromCache } = useOffline();
  const [data, setData] = useState<T | null>(options?.fallbackData ?? null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    async function fetchData() {
      const cacheKey = options?.cacheKey ?? key;
      
      // Try cache first if offline
      if (!isOnline) {
        const cached = getFromCache<T>(cacheKey);
        if (cached) {
          setData(cached);
          setIsLoading(false);
          return;
        }
      }

      // Fetch from API
      try {
        const result = await queryFn();
        setData(result);
        
        // Cache the result
        cacheForOffline(cacheKey, result, options?.cacheTtl);
      } catch (err) {
        // If online fetch fails, try cache
        const cached = getFromCache<T>(cacheKey);
        if (cached) {
          setData(cached);
        } else {
          setError(err as Error);
        }
      } finally {
        setIsLoading(false);
      }
    }

    fetchData();
  }, [key, isOnline]);

  return { data, isLoading, error, isOnline };
}

export default useOffline;
