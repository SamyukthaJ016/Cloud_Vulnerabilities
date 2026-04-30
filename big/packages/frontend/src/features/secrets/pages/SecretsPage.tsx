import { ComingSoon } from '@/components/ComingSoon';

export function SecretsPage() {
  return (
    <ComingSoon
      title="Secrets"
      description="Manage scanner credentials. Values live in Vault — only metadata is shown here."
      flowNodes="X3, Y → AG"
    />
  );
}
