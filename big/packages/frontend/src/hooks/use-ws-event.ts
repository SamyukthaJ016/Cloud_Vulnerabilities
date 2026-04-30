import { useEffect } from 'react';
import type { NotificationEvent, NotificationPayloadMap } from '@cloudguard/shared';
import { useWebSocket } from '@/features/notifications/WebSocketProvider';

/**
 * Subscribe to a WebSocket event for the duration of the component lifecycle.
 * Handler is called on every matching event; invalidate queries / show toasts from here.
 *
 * @example
 *   useWsEvent('scan.completed', ({ scanJobId }) => {
 *     qc.invalidateQueries({ queryKey: ['scan', scanJobId] });
 *   });
 */
export function useWsEvent<E extends NotificationEvent>(
  event: E,
  handler: (payload: NotificationPayloadMap[E]) => void,
) {
  const socket = useWebSocket();

  useEffect(() => {
    if (!socket) return;
    const onEvent = (payload: NotificationPayloadMap[E]) => handler(payload);
    (socket as any).on(event, onEvent);
    return () => {
      (socket as any).off(event, onEvent);
    };
  }, [socket, event, handler]);
}
