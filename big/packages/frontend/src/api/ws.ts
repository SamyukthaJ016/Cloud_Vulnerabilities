import { io, Socket } from 'socket.io-client';

/**
 * Creates the Socket.IO client for the notifications gateway.
 * Called once by WebSocketProvider. Auth is via JWT cookie (shared with HTTP).
 */
export function createSocket(): Socket<any, any> {
  const base = import.meta.env.VITE_WS_BASE_URL ?? '/ws';
  return io(base, {
    withCredentials: true,
    transports: ['websocket'],
    autoConnect: false,
  });
}
