import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { format, formatDistanceToNow } from 'date-fns';

/** shadcn/ui standard helper: merge tailwind classes with conflict resolution. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string | Date, pattern = 'dd MMM yyyy, HH:mm') {
  return format(typeof iso === 'string' ? new Date(iso) : iso, pattern);
}

export function formatRelative(iso: string | Date) {
  return formatDistanceToNow(typeof iso === 'string' ? new Date(iso) : iso, {
    addSuffix: true,
  });
}

/** Convert paise (INR lowest unit) to a display string like "₹4,999.00". */
export function formatPaise(paise: number, currency = 'INR') {
  const rupees = paise / 100;
  return new Intl.NumberFormat('en-IN', { style: 'currency', currency }).format(rupees);
}
