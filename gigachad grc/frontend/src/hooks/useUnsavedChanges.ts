import { useCallback, useState } from 'react';
import { useBeforeUnload, useBlocker } from 'react-router-dom';

interface UseUnsavedChangesOptions {
  /** Message to show in the browser's native dialog */
  message?: string;
  /** Whether there are unsaved changes */
  hasChanges: boolean;
}

/**
 * Hook to warn users about unsaved changes before leaving a page
 * Works with both browser navigation (back/forward/close) and React Router navigation
 */
export function useUnsavedChanges({
  message = 'You have unsaved changes. Are you sure you want to leave?',
  hasChanges,
}: UseUnsavedChangesOptions) {
  // Warn on browser navigation (close tab, refresh, back/forward)
  useBeforeUnload(
    useCallback(
      (event: BeforeUnloadEvent) => {
        if (hasChanges) {
          event.preventDefault();
          // Most browsers ignore custom messages and show their own
          event.returnValue = message;
          return message;
        }
      },
      [hasChanges, message]
    )
  );

  // Block React Router navigation
  const blocker = useBlocker(
    useCallback(
      ({ currentLocation, nextLocation }: { currentLocation: any; nextLocation: any }) => {
        return hasChanges && currentLocation.pathname !== nextLocation.pathname;
      },
      [hasChanges]
    )
  );

  return {
    blocker,
    isBlocked: blocker.state === 'blocked',
    proceed: () => blocker.proceed?.(),
    reset: () => blocker.reset?.(),
  };
}

/**
 * Hook to track form dirty state
 * Returns a simple isDirty flag and functions to mark as dirty/clean
 */
export function useFormDirtyState(initialDirty = false) {
  const [isDirty, setIsDirty] = useState(initialDirty);

  const markDirty = useCallback(() => setIsDirty(true), []);
  const markClean = useCallback(() => setIsDirty(false), []);
  const reset = useCallback(() => setIsDirty(initialDirty), [initialDirty]);

  return {
    isDirty,
    markDirty,
    markClean,
    reset,
  };
}

export default useUnsavedChanges;

