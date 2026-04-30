import { useState, useEffect, useCallback } from 'react';
import { WifiIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import clsx from 'clsx';

interface NetworkStatusProps {
  className?: string;
}

/**
 * NetworkStatus - Displays connectivity status and reconnection alerts
 * Shows a banner when offline and a reconnection message when back online
 */
export default function NetworkStatus({ className }: NetworkStatusProps) {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [showReconnected, setShowReconnected] = useState(false);
  const [wasOffline, setWasOffline] = useState(false);

  const handleOnline = useCallback(() => {
    setIsOnline(true);
    if (wasOffline) {
      setShowReconnected(true);
      // Hide reconnection message after 3 seconds
      setTimeout(() => setShowReconnected(false), 3000);
    }
  }, [wasOffline]);

  const handleOffline = useCallback(() => {
    setIsOnline(false);
    setWasOffline(true);
    setShowReconnected(false);
  }, []);

  useEffect(() => {
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [handleOnline, handleOffline]);

  // Don't render anything if online and no reconnection message
  if (isOnline && !showReconnected) {
    return null;
  }

  return (
    <div className={clsx('fixed top-0 left-0 right-0 z-50', className)}>
      {!isOnline && (
        <div className="bg-red-600 text-white px-4 py-2 flex items-center justify-center gap-2 text-sm animate-fade-in">
          <ExclamationTriangleIcon className="w-5 h-5" />
          <span>
            <strong>You're offline.</strong> Some features may be unavailable until you reconnect.
          </span>
        </div>
      )}
      {showReconnected && (
        <div className="bg-green-600 text-white px-4 py-2 flex items-center justify-center gap-2 text-sm animate-fade-in">
          <WifiIcon className="w-5 h-5" />
          <span>
            <strong>You're back online!</strong> All features are now available.
          </span>
        </div>
      )}
    </div>
  );
}

