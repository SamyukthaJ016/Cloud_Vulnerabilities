import { forwardRef, ButtonHTMLAttributes, ReactNode } from 'react';
import { clsx } from 'clsx';

// ===========================================
// Loading Spinner
// ===========================================

function LoadingSpinner({ className }: { className?: string }) {
  return (
    <svg
      className={clsx('animate-spin', className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

// ===========================================
// Button Variants
// ===========================================

const variants = {
  primary: 'btn-variant-primary',
  secondary: 'btn-variant-secondary',
  success: 'btn-variant-success',
  danger: 'btn-variant-danger',
  warning: 'btn-variant-warning',
  outline: 'btn-variant-outline',
  ghost: 'btn-variant-ghost',
  link: 'btn-variant-link',
};

const sizes = {
  xs: 'px-2 py-1 text-xs',
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-base',
  xl: 'px-6 py-3 text-lg',
};

const iconSizes = {
  xs: 'h-3 w-3',
  sm: 'h-4 w-4',
  md: 'h-4 w-4',
  lg: 'h-5 w-5',
  xl: 'h-6 w-6',
};

// ===========================================
// Button Component
// ===========================================

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  isLoading?: boolean;
  loadingText?: string;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  fullWidth?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      loadingText,
      leftIcon,
      rightIcon,
      fullWidth = false,
      disabled,
      children,
      ...props
    },
    ref
  ) => {
    const isDisabled = disabled || isLoading;

    return (
      <button
        ref={ref}
        className={clsx(
          'inline-flex items-center justify-center font-medium rounded-md transition-colors',
          'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-primary)]',
          'disabled:cursor-not-allowed',
          variants[variant],
          sizes[size],
          fullWidth && 'w-full',
          className
        )}
        disabled={isDisabled}
        {...props}
      >
        {isLoading ? (
          <>
            <LoadingSpinner className={clsx(iconSizes[size], 'mr-2')} />
            {loadingText || children}
          </>
        ) : (
          <>
            {leftIcon && (
              <span className={clsx('mr-2', iconSizes[size])}>{leftIcon}</span>
            )}
            {children}
            {rightIcon && (
              <span className={clsx('ml-2', iconSizes[size])}>{rightIcon}</span>
            )}
          </>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';

// ===========================================
// Icon Button Component
// ===========================================

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  isLoading?: boolean;
  icon: ReactNode;
  'aria-label': string;
}

const iconButtonSizes = {
  xs: 'p-1',
  sm: 'p-1.5',
  md: 'p-2',
  lg: 'p-2.5',
  xl: 'p-3',
};

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  (
    {
      className,
      variant = 'ghost',
      size = 'md',
      isLoading = false,
      icon,
      disabled,
      ...props
    },
    ref
  ) => {
    const isDisabled = disabled || isLoading;

    return (
      <button
        ref={ref}
        className={clsx(
          'inline-flex items-center justify-center rounded-md transition-colors',
          'focus:outline-none focus:ring-2 focus:ring-offset-2',
          'disabled:cursor-not-allowed',
          variants[variant],
          iconButtonSizes[size],
          className
        )}
        disabled={isDisabled}
        {...props}
      >
        {isLoading ? (
          <LoadingSpinner className={iconSizes[size]} />
        ) : (
          <span className={iconSizes[size]}>{icon}</span>
        )}
      </button>
    );
  }
);

IconButton.displayName = 'IconButton';

// ===========================================
// Button Group Component
// ===========================================

interface ButtonGroupProps {
  children: ReactNode;
  className?: string;
  attached?: boolean;
}

export function ButtonGroup({ children, className, attached = false }: ButtonGroupProps) {
  return (
    <div
      className={clsx(
        'inline-flex',
        attached && '[&>button]:rounded-none [&>button:first-child]:rounded-l-md [&>button:last-child]:rounded-r-md [&>button:not(:last-child)]:border-r-0',
        !attached && 'space-x-2',
        className
      )}
    >
      {children}
    </div>
  );
}

export default Button;

