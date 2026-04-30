import { PropsWithChildren } from 'react';
import { QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Toaster } from 'sonner';
import { queryClient } from './query-client';
import { ErrorBoundary } from './error-boundary';
import { WebSocketProvider } from '@/features/notifications/WebSocketProvider';

/**
 * Wraps the entire app: query client, error boundary, websocket provider, toast host.
 * Route-level providers (e.g. theme per route) go inside the router, not here.
 */
export function Providers({ children }: PropsWithChildren) {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <WebSocketProvider>
          {children}
          <Toaster position="top-right" richColors closeButton />
          {import.meta.env.DEV && <ReactQueryDevtools initialIsOpen={false} />}
        </WebSocketProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
