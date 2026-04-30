import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bell, ChevronDown, LogOut, User } from 'lucide-react';
import { useCurrentUser } from '@/hooks/use-current-user';
import { useLogout } from '@/features/auth';
import { cn } from '@/lib/utils';

export function TopBar() {
  const user = useCurrentUser();
  const logout = useLogout();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close menu on outside click
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const initial = (user?.email ?? '?').charAt(0).toUpperCase();

  return (
    <header className="flex h-14 items-center justify-between border-b bg-background px-6">
      <div className="text-sm font-medium text-muted-foreground">
        {/* Breadcrumbs / page title — features can portal into here later */}
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label="Notifications"
          className="relative inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <Bell className="h-4 w-4" />
          {/* TODO: badge dot when realtime.store has unread events */}
        </button>

        <div ref={ref} className="relative">
          <button
            type="button"
            onClick={() => setOpen((s) => !s)}
            className="flex items-center gap-2 rounded-md border bg-background px-2 py-1.5 text-sm hover:bg-muted"
            aria-haspopup="menu"
            aria-expanded={open ? 'true' : 'false'}
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
              {initial}
            </span>
            <span className="hidden max-w-[160px] truncate text-muted-foreground sm:inline">
              {user?.email ?? '...'}
            </span>
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          </button>

          {open && (
            <div
              role="menu"
              className={cn(
                'absolute right-0 z-50 mt-2 w-56 overflow-hidden rounded-md border bg-popover shadow-lg',
                'animate-in fade-in-0 zoom-in-95',
              )}
            >
              <div className="border-b px-3 py-2 text-xs text-muted-foreground">
                <p className="truncate font-medium text-foreground">{user?.email ?? '—'}</p>
                <p className="truncate">{user?.roleKey ?? 'no role'}</p>
              </div>
              <Link
                to="/settings/profile"
                role="menuitem"
                onClick={() => setOpen(false)}
                className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-muted"
              >
                <User className="h-4 w-4" />
                Profile
              </Link>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  logout.mutate();
                }}
                className="flex w-full items-center gap-2 border-t px-3 py-2 text-left text-sm text-red-600 hover:bg-muted"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
