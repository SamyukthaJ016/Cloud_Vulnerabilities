import { describe, it, expect } from 'vitest';
import { render } from '@/test/utils';
import { Skeleton, SkeletonText, SkeletonTitle, SkeletonCard, SkeletonTable } from './Skeleton';

describe('Skeleton', () => {
  it('renders a skeleton element', () => {
    const { container } = render(<Skeleton />);
    
    expect(container.firstChild).toBeInTheDocument();
    expect(container.firstChild).toHaveClass('animate-pulse');
  });

  it('applies custom className', () => {
    const { container } = render(<Skeleton className="custom-skeleton" />);
    
    expect(container.firstChild).toHaveClass('custom-skeleton');
  });

  it('can disable animation', () => {
    const { container } = render(<Skeleton animate={false} />);
    
    expect(container.firstChild).not.toHaveClass('animate-pulse');
  });

  it('has default background color', () => {
    const { container } = render(<Skeleton />);
    
    expect(container.firstChild).toHaveClass('bg-surface-700');
  });

  it('is rounded by default', () => {
    const { container } = render(<Skeleton />);
    
    expect(container.firstChild).toHaveClass('rounded');
  });
});

describe('SkeletonText', () => {
  it('renders default 3 lines', () => {
    const { container } = render(<SkeletonText />);
    
    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBe(3);
  });

  it('renders custom number of lines', () => {
    const { container } = render(<SkeletonText lines={5} />);
    
    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBe(5);
  });
});

describe('SkeletonTitle', () => {
  it('renders title skeleton', () => {
    const { container } = render(<SkeletonTitle />);
    
    expect(container.firstChild).toBeInTheDocument();
  });
});

describe('SkeletonCard', () => {
  it('renders card skeleton', () => {
    const { container } = render(<SkeletonCard />);
    
    expect(container.firstChild).toBeInTheDocument();
  });
});

describe('SkeletonTable', () => {
  it('renders table skeleton with default rows', () => {
    const { container } = render(<SkeletonTable />);
    
    expect(container.firstChild).toBeInTheDocument();
  });

  it('renders table skeleton with custom rows', () => {
    const { container } = render(<SkeletonTable rows={10} />);
    
    expect(container.firstChild).toBeInTheDocument();
  });
});
