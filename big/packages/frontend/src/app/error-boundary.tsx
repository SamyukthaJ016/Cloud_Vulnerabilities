import { Component, ErrorInfo, PropsWithChildren } from 'react';

interface State {
  error: Error | null;
}

/**
 * Last-resort error boundary. Route-level errors are caught by
 * react-router's errorElement; this only catches provider-level crashes.
 */
export class ErrorBoundary extends Component<PropsWithChildren, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // TODO: hook Sentry / logging
    console.error('App error boundary caught:', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center p-8">
          <div className="max-w-md space-y-4 text-center">
            <h1 className="text-2xl font-semibold">Something went wrong</h1>
            <p className="text-muted-foreground">
              Please refresh the page. If the problem persists, contact support.
            </p>
            <pre className="overflow-auto rounded bg-muted p-4 text-left text-xs">
              {this.state.error.message}
            </pre>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
