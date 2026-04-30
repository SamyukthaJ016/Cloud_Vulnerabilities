import { NavLink } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Building2,
  CreditCard,
  Key,
  LayoutDashboard,
  type LucideIcon,
  Radar,
  ScrollText,
  Settings,
  Shield,
  User,
  Users,
  Webhook,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

/**
 * Sidebar nav. Sections mirror the flow-diagram domains so the team
 * can find a feature by what it does, not where it lives in code.
 */
const SECTIONS: NavSection[] = [
  {
    label: 'Overview',
    items: [{ to: '/', label: 'Overview', icon: LayoutDashboard, end: true }],
  },
  {
    label: 'Security',
    items: [
      { to: '/scanners', label: 'Scanners', icon: Radar },
      { to: '/scans', label: 'Scans', icon: Activity },
      { to: '/findings', label: 'Findings', icon: AlertTriangle },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { to: '/secrets', label: 'Secrets', icon: Key },
      { to: '/settings/webhooks', label: 'Webhooks', icon: Webhook },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { to: '/billing', label: 'Billing', icon: CreditCard },
      { to: '/audit', label: 'Audit log', icon: ScrollText },
    ],
  },
  {
    label: 'Settings',
    items: [
      { to: '/settings/profile', label: 'Profile', icon: User },
      { to: '/settings/organization', label: 'Organization', icon: Building2 },
      { to: '/settings/members', label: 'Members', icon: Users },
    ],
  },
];

export function Sidebar() {
  return (
    <aside className="flex w-60 flex-col border-r bg-background">
      <div className="flex h-14 items-center gap-2 border-b px-5">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <Shield className="h-4 w-4" />
        </div>
        <span className="text-sm font-semibold tracking-tight">CloudGuard</span>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {SECTIONS.map((section) => (
          <div key={section.label} className="mb-5 last:mb-0">
            <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {section.label}
            </p>
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition',
                        isActive
                          ? 'bg-primary text-primary-foreground'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                      )
                    }
                  >
                    <item.icon className="h-4 w-4 shrink-0" aria-hidden />
                    <span>{item.label}</span>
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="border-t px-3 py-3">
        <NavLink
          to="/settings/profile"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 rounded-md px-3 py-1.5 text-xs',
              isActive
                ? 'text-foreground'
                : 'text-muted-foreground hover:text-foreground',
            )
          }
        >
          <Settings className="h-3.5 w-3.5" aria-hidden />
          Settings
        </NavLink>
      </div>
    </aside>
  );
}
