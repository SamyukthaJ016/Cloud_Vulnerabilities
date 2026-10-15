import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
vi.unmock('@/contexts/ModuleContext');
import { ModuleProvider, useModules } from './ModuleContext';

function Probe() {
  const modules = useModules();
  return <span>{modules.isRouteEnabled('/cloudguard-grc') ? 'connector visible' : 'connector hidden'}</span>;
}

describe('CloudGuard connector navigation', () => {
  it('shows the connector when the compliance module is enabled', () => {
    render(<ModuleProvider overrideModules={['compliance']}><Probe /></ModuleProvider>);
    expect(screen.getByText('connector visible')).toBeInTheDocument();
  });
  it('respects a disabled compliance module', () => {
    render(<ModuleProvider overrideModules={['risk']}><Probe /></ModuleProvider>);
    expect(screen.getByText('connector hidden')).toBeInTheDocument();
  });
});
