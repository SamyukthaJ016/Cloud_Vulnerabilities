import { createBrowserRouter, Navigate } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { AuthLayout } from '@/components/layout/AuthLayout';
import { RequireAuth } from '@/features/auth/guards/RequireAuth';
import { RequireRole } from '@/features/auth/guards/RequireRole';
import { SYSTEM_ROLE_KEYS } from '@cloudguard/shared';

// Route pages are imported from each feature's barrel (index.ts).
// Keep this file the single place to see the whole URL space.
import { LoginPage, AuthCallbackPage, AuthErrorPage, OnboardingPage } from '@/features/auth';
import { DashboardPage } from '@/features/dashboard';
import { SecretsPage } from '@/features/secrets';
import { ScannersPage } from '@/features/scanners';
import { ScansListPage, ScanDetailPage } from '@/features/scans';
import { FindingsListPage, FindingDetailPage } from '@/features/findings';
import { BillingPage } from '@/features/billing';
import { PlansPage } from '@/features/plans';
import { OrgSettingsPage, MembersPage } from '@/features/organizations';
import { ProfileSettingsPage } from '@/features/users';
import { WebhooksPage } from '@/features/webhooks-outbound';
import { AuditLogPage } from '@/features/audit';

export const router = createBrowserRouter([
  // Public / auth
  {
    element: <AuthLayout />,
    children: [
      { path: '/login', element: <LoginPage /> },
      { path: '/auth/callback', element: <AuthCallbackPage /> },
      { path: '/auth/error', element: <AuthErrorPage /> },
      { path: '/onboarding', element: <OnboardingPage /> },
    ],
  },

  // Authenticated app
  {
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <DashboardPage /> },

      { path: 'secrets', element: <SecretsPage /> },

      { path: 'scanners', element: <ScannersPage /> },

      { path: 'scans', element: <ScansListPage /> },
      { path: 'scans/:id', element: <ScanDetailPage /> },

      { path: 'findings', element: <FindingsListPage /> },
      { path: 'findings/:id', element: <FindingDetailPage /> },

      { path: 'billing', element: <BillingPage /> },
      { path: 'billing/plans', element: <PlansPage /> },

      { path: 'audit', element: <AuditLogPage /> },

      {
        path: 'settings',
        children: [
          { index: true, element: <Navigate to="/settings/profile" replace /> },
          { path: 'profile', element: <ProfileSettingsPage /> },
          {
            path: 'organization',
            element: (
              <RequireRole role={SYSTEM_ROLE_KEYS.ORG_ADMIN}>
                <OrgSettingsPage />
              </RequireRole>
            ),
          },
          {
            path: 'members',
            element: (
              <RequireRole role={SYSTEM_ROLE_KEYS.ORG_ADMIN}>
                <MembersPage />
              </RequireRole>
            ),
          },
          {
            path: 'webhooks',
            element: (
              <RequireRole role={SYSTEM_ROLE_KEYS.ORG_ADMIN}>
                <WebhooksPage />
              </RequireRole>
            ),
          },
        ],
      },
    ],
  },

  { path: '*', element: <Navigate to="/" replace /> },
]);
