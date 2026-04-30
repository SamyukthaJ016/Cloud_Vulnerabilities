import { forwardRef, InputHTMLAttributes, ReactNode, useId } from 'react';
import clsx from 'clsx';

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string;
  error?: string;
  hint?: string;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  fullWidth?: boolean;
}

const sizeStyles = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-3 py-2 text-sm',
  lg: 'px-4 py-3 text-base',
};

/**
 * Accessible Input Component
 * 
 * Features:
 * - Automatic label association with unique IDs
 * - Error state with aria-invalid and aria-describedby
 * - Hint text support
 * - Screen reader friendly
 */
export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      hint,
      leftIcon,
      rightIcon,
      size = 'md',
      fullWidth = false,
      className,
      id: providedId,
      required,
      disabled,
      type = 'text',
      ...props
    },
    ref
  ) => {
    // Generate unique IDs for accessibility
    const generatedId = useId();
    const id = providedId || generatedId;
    const errorId = `${id}-error`;
    const hintId = `${id}-hint`;

    // Build aria-describedby from available descriptions
    const describedBy = [
      error && errorId,
      hint && !error && hintId,
    ].filter(Boolean).join(' ') || undefined;

    return (
      <div className={clsx('flex flex-col gap-1', fullWidth && 'w-full')}>
        {label && (
          <label
            htmlFor={id}
            className="text-sm font-medium text-surface-300"
          >
            {label}
            {required && (
              <span className="text-red-500 ml-1" aria-hidden="true">*</span>
            )}
            {required && <span className="sr-only">(required)</span>}
          </label>
        )}
        
        <div className="relative">
          {leftIcon && (
            <div 
              className="absolute left-3 top-1/2 -translate-y-1/2 text-surface-500"
              aria-hidden="true"
            >
              {leftIcon}
            </div>
          )}
          
          <input
            ref={ref}
            id={id}
            type={type}
            disabled={disabled}
            required={required}
            aria-invalid={error ? 'true' : undefined}
            aria-describedby={describedBy}
            aria-required={required}
            className={clsx(
              'w-full rounded-lg border bg-surface-900 text-surface-100',
              'placeholder:text-surface-500',
              'transition-colors duration-200',
              'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-surface-900',
              error
                ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                : 'border-surface-700 focus:border-blue-500 focus:ring-blue-500',
              disabled && 'opacity-60 cursor-not-allowed bg-surface-800',
              leftIcon && 'pl-10',
              rightIcon && 'pr-10',
              sizeStyles[size],
              className
            )}
            {...props}
          />
          
          {rightIcon && (
            <div 
              className="absolute right-3 top-1/2 -translate-y-1/2 text-surface-500"
              aria-hidden="true"
            >
              {rightIcon}
            </div>
          )}
        </div>

        {error && (
          <p 
            id={errorId} 
            className="text-sm text-red-500"
            role="alert"
            aria-live="polite"
          >
            {error}
          </p>
        )}

        {hint && !error && (
          <p id={hintId} className="text-sm text-surface-500">
            {hint}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

export default Input;

