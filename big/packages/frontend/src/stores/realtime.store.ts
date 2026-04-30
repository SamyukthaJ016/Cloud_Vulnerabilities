import { create } from 'zustand';
import type { NotificationEvent, NotificationPayloadMap } from '@cloudguard/shared';

interface RealtimeEvent<E extends NotificationEvent = NotificationEvent> {
  event: E;
  payload: NotificationPayloadMap[E];
  receivedAt: number;
}

interface RealtimeState {
  recent: RealtimeEvent[];
  push: <E extends NotificationEvent>(event: E, payload: NotificationPayloadMap[E]) => void;
  clear: () => void;
}

/**
 * Tiny ring buffer of recent WebSocket events. Used for the activity
 * indicator in the topbar + as a fallback for features that want a
 * replay of events (e.g. scan detail page loaded after completion).
 */
const MAX_RECENT = 100;

export const useRealtimeStore = create<RealtimeState>((set) => ({
  recent: [],
  push: (event, payload) =>
    set((s) => ({
      recent: [{ event, payload, receivedAt: Date.now() } as RealtimeEvent, ...s.recent].slice(
        0,
        MAX_RECENT,
      ),
    })),
  clear: () => set({ recent: [] }),
}));
