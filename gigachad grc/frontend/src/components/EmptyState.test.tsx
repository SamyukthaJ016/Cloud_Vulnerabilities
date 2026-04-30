import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import EmptyState from './EmptyState';
import { PlusIcon } from '@heroicons/react/24/outline';

describe('EmptyState', () => {
  it('renders with title and description', () => {
    render(
      <EmptyState
        title="No Items Found"
        description="Get started by creating your first item."
      />
    );
    
    expect(screen.getByText('No Items Found')).toBeInTheDocument();
    expect(screen.getByText('Get started by creating your first item.')).toBeInTheDocument();
  });

  it('renders with action button', () => {
    const handleClick = vi.fn();
    
    render(
      <EmptyState
        title="No Items"
        description="Create an item to get started."
        action={{
          label: "Create Item",
          onClick: handleClick,
        }}
      />
    );
    
    const button = screen.getByRole('button', { name: /Create Item/i });
    expect(button).toBeInTheDocument();
    
    fireEvent.click(button);
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('renders without action button when no action provided', () => {
    render(
      <EmptyState
        title="No Items"
        description="Nothing to see here."
      />
    );
    
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('renders custom icon when provided', () => {
    render(
      <EmptyState
        title="No Items"
        description="Nothing here."
        icon={<PlusIcon data-testid="custom-icon" className="w-6 h-6" />}
      />
    );
    
    expect(screen.getByTestId('custom-icon')).toBeInTheDocument();
  });

  it('renders with variant icon', () => {
    const { container } = render(
      <EmptyState
        title="No Documents"
        description="No documents available."
        variant="documents"
      />
    );
    
    // The document icon should be rendered
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(
      <EmptyState
        title="No Items"
        description="Nothing here."
        className="custom-class"
      />
    );
    
    expect(container.firstChild).toHaveClass('custom-class');
  });

  it('renders secondary action when provided', () => {
    const handleSecondary = vi.fn();
    
    render(
      <EmptyState
        title="No Items"
        description="Create an item to get started."
        action={{
          label: "Create Item",
          onClick: vi.fn(),
        }}
        secondaryAction={{
          label: "Learn More",
          onClick: handleSecondary,
        }}
      />
    );
    
    const secondaryButton = screen.getByRole('button', { name: /Learn More/i });
    expect(secondaryButton).toBeInTheDocument();
    
    fireEvent.click(secondaryButton);
    expect(handleSecondary).toHaveBeenCalledTimes(1);
  });
});
