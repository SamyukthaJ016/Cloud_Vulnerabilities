import { FormEvent, useState } from 'react';
import { Plus, Trash2, X } from 'lucide-react';
import { SYSTEM_ROLE_KEYS, SystemRoleKey } from '@cloudguard/shared';
import { useApiErrorToast } from '@/api/errors';
import { useCurrentUser } from '@/hooks/use-current-user';
import { cn, formatRelative } from '@/lib/utils';
import {
  useInviteMember,
  useMembersQuery,
  useRemoveMember,
} from '../api/organizations.api';

const ROLE_OPTIONS: { value: SystemRoleKey; label: string }[] = [
  { value: SYSTEM_ROLE_KEYS.ORG_ADMIN, label: 'Admin' },
  { value: SYSTEM_ROLE_KEYS.ORG_MEMBER, label: 'Member' },
  { value: SYSTEM_ROLE_KEYS.SCANNER_OPERATOR, label: 'Scanner operator' },
  { value: SYSTEM_ROLE_KEYS.VIEWER, label: 'Viewer' },
];

export function MembersPage() {
  const me = useCurrentUser();
  const { data: members, isLoading } = useMembersQuery();
  const [inviteOpen, setInviteOpen] = useState(false);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Members</h1>
          <p className="text-sm text-muted-foreground">
            Invite teammates and manage their roles.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setInviteOpen(true)}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          <Plus className="h-4 w-4" />
          Invite member
        </button>
      </div>

      <div className="rounded-xl border bg-card">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Loading...</div>
        ) : !members || members.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">No members yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-5 py-3 font-medium">Member</th>
                <th className="px-5 py-3 font-medium">Role</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Joined</th>
                <th className="px-5 py-3 font-medium">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {members.map((m) => (
                <MemberRow
                  key={m.id}
                  member={m}
                  isSelf={m.user.id === me?.userId}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

      {inviteOpen && <InviteDialog onClose={() => setInviteOpen(false)} />}
    </div>
  );
}

function MemberRow({
  member,
  isSelf,
}: {
  member: import('@cloudguard/shared').OrgMemberDto;
  isSelf: boolean;
}) {
  const removeMember = useRemoveMember();
  const toastError = useApiErrorToast();

  const onRemove = async () => {
    if (!confirm(`Remove ${member.user.email}?`)) return;
    try {
      await removeMember.mutateAsync(member.user.id);
    } catch (err) {
      toastError(err);
    }
  };

  return (
    <tr>
      <td className="px-5 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-semibold">
            {(member.user.name ?? member.user.email).charAt(0).toUpperCase()}
          </div>
          <div className="leading-tight">
            <div className="font-medium">
              {member.user.name ?? member.user.email}
              {isSelf && <span className="ml-1 text-xs text-muted-foreground">(you)</span>}
            </div>
            {member.user.name && (
              <div className="text-xs text-muted-foreground">{member.user.email}</div>
            )}
          </div>
        </div>
      </td>
      <td className="px-5 py-3 text-muted-foreground">{member.role.name}</td>
      <td className="px-5 py-3">
        <StatusBadge status={member.status} />
      </td>
      <td className="px-5 py-3 text-xs text-muted-foreground">
        {formatRelative(member.joinedAt)}
      </td>
      <td className="px-5 py-3 text-right">
        {!isSelf && (
          <button
            type="button"
            aria-label="Remove member"
            onClick={onRemove}
            disabled={removeMember.isPending}
            className="rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-red-600 disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </td>
    </tr>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    ACTIVE: 'bg-emerald-500/10 text-emerald-700',
    INVITED: 'bg-amber-500/10 text-amber-700',
    SUSPENDED: 'bg-red-500/10 text-red-700',
  };
  return (
    <span
      className={cn(
        'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
        styles[status] ?? 'bg-muted text-muted-foreground',
      )}
    >
      {status.toLowerCase()}
    </span>
  );
}

function InviteDialog({ onClose }: { onClose: () => void }) {
  const inviteMember = useInviteMember();
  const toastError = useApiErrorToast();
  const [email, setEmail] = useState('');
  const [roleKey, setRoleKey] = useState<SystemRoleKey>(SYSTEM_ROLE_KEYS.ORG_MEMBER);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await inviteMember.mutateAsync({ email: email.trim(), roleKey });
      onClose();
    } catch (err) {
      toastError(err);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md space-y-4 rounded-lg border bg-card p-6 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">Invite member</h2>
            <p className="mt-0.5 text-sm text-muted-foreground">
              They'll join when they sign in with this email via Google.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-muted-foreground hover:bg-muted"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-sm font-medium">Email</label>
            <input
              type="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="teammate@acme.com"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="invite-role" className="text-sm font-medium">
              Role
            </label>
            <select
              id="invite-role"
              value={roleKey}
              onChange={(e) => setRoleKey(e.target.value as SystemRoleKey)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={inviteMember.isPending || !email.trim()}
              className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
            >
              {inviteMember.isPending ? 'Sending...' : 'Send invite'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
