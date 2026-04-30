import { createContext, PropsWithChildren, useContext, useEffect, useState } from 'react';
import type { Socket } from 'socket.io-client';
import { createSocket } from '@/api/ws';
import { useRealtimeStore } from '@/stores/realtime.store';
import { useCurrentUser } from '@/hooks/use-current-user';
import type { NotificationEvent } from '@cloudguard/shared';

const SocketContext = createContext<Socket<any, any> | null>(null);

/** Returns the current socket or null if the user isn't logged in yet. */
export function useWebSocket() {
  return useContext(SocketContext);
}

/**
 * Mounts the Socket.IO client once the user is authenticated, joins the
 * org room (backend uses `org:<orgId>` internally), and pushes every event
 * into the realtime ring buffer.
 *
 * Features subscribe to specific events via `useWsEvent(name, handler)`.
 */
export function WebSocketProvider({ children }: PropsWithChildren) {
  const user = useCurrentUser();
  const push = useRealtimeStore((s) => s.push);
  const [socket, setSocket] = useState<Socket<any, any> | null>(null);

  useEffect(() => {
    if (!user?.orgId) return;
    const s = createSocket();
    s.connect();

    const events: NotificationEvent[] = [
      'scan.dispatched',
      'scan.completed',
      'scan.failed',
      'finding.created',
      'billing.updated',
      'secret.changed',
    ];
    for (const e of events) {
      // push into the ring buffer; feature-level hooks handle side effects.
      s.on(e, (payload: unknown) => push(e, payload as never));
    }

    setSocket(s);
    return () => {
      s.disconnect();
      setSocket(null);
    };
  }, [user?.orgId, push]);

  return <SocketContext.Provider value={socket}>{children}</SocketContext.Provider>;
}
