import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2 } from 'lucide-react';
import { useCurrentUser } from '@/hooks/use-current-user';
import { useApiErrorToast } from '@/api/errors';
import { useCreateOrganization } from '@/features/organizations';

/**
 * Flow N1 → escape via self-serve org creation (Pattern A).
 *
 * The user has just signed in but has no membership. They give the org a name,
 * an editable slug (defaults derived from the name), and optionally a domain
 * for auto-join. Submission creates Organization + admin OrgMember in one
 * transaction; backend re-issues the JWT cookie with the new orgId; we
 * invalidate /auth/me and the RequireAuth guard re-evaluates → dashboard.
 */
export function OnboardingPage() {
  const user = useCurrentUser();
  const navigate = useNavigate();
  const toastError = useApiErrorToast();
  const createOrg = useCreateOrganization();

  const emailDomain = user?.email?.split('@')[1] ?? '';

  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [domain, setDomain] = useState(emailDomain);
  const [enableAutoJoin, setEnableAutoJoin] = useState(true);

  // Auto-derive slug from name until the user edits it manually.
  useEffect(() => {
    if (!slugTouched) setSlug(slugify(name));
  }, [name, slugTouched]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await createOrg.mutateAsync({
        name: name.trim(),
        slug: slug.trim(),
        domain: enableAutoJoin && domain ? domain.trim().toLowerCase() : undefined,
      });
      navigate('/', { replace: true });
    } catch (err) {
      toastError(err);
    }
  };

  const submitDisabled =
    createOrg.isPending || name.trim().length < 2 || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug);

  return (
    <div className="space-y-6">
      <div className="flex flex-col items-center space-y-3 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <Building2 className="h-6 w-6" aria-hidden />
        </div>
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">Create your organization</h1>
          <p className="text-sm text-muted-foreground">
            Signed in as <span className="font-medium text-foreground">{user?.email}</span>
          </p>
        </div>
      </div>

      <form onSubmit={onSubmit} className="space-y-4">
        <Field
          label="Organization name"
          hint="The name your team will see across CloudGuard."
        >
          <input
            type="text"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme Corp"
            className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            required
            minLength={2}
            maxLength={80}
          />
        </Field>

        <Field
          label="URL slug"
          hint="Used in URLs. Lowercase letters, numbers, dashes."
        >
          <input
            type="text"
            value={slug}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value.toLowerCase());
            }}
            placeholder="acme-corp"
            className="w-full rounded-md border bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
            required
            maxLength={40}
          />
        </Field>

        <div className="rounded-md border bg-muted/30 p-3">
          <label className="flex items-start gap-3 text-sm">
            <input
              type="checkbox"
              checked={enableAutoJoin}
              onChange={(e) => setEnableAutoJoin(e.target.checked)}
              className="mt-0.5"
            />
            <div className="space-y-1">
              <span className="font-medium">
                Allow anyone with{' '}
                <span className="font-mono text-xs">@{emailDomain || 'your-domain.com'}</span> to
                auto-join
              </span>
              <p className="text-xs text-muted-foreground">
                New sign-ins from this domain become members automatically. You can change this in
                Settings → Organization later.
              </p>
            </div>
          </label>
          {enableAutoJoin && (
            <div className="mt-3 pl-6">
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value.toLowerCase())}
                placeholder="acme.com"
                className="w-full rounded-md border bg-background px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                pattern="^[a-z0-9]+(\.[a-z0-9-]+)*\.[a-z]{2,}$"
              />
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={submitDisabled}
          className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition disabled:opacity-50"
        >
          {createOrg.isPending ? 'Creating...' : 'Create organization'}
        </button>
      </form>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-sm font-medium">{label}</label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}
