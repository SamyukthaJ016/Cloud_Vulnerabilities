/**
 * Dynamic discovery of scanner env slots.
 *
 * A scanner slot is any pair of env vars matching:
 *   SCANNER_<N>_BASE_URL          (required)
 *   SCANNER_<N>_SHARED_SECRET     (required for signed dispatch + callback verify)
 *
 * Adding a scanner = set the two env vars and restart (or hit the admin refresh
 * endpoint). No code change needed.
 */

const BASE_URL_PATTERN = /^SCANNER_(\d+)_BASE_URL$/;

export interface ScannerEnvSlot {
  index: string;          // the digits between SCANNER_ and _BASE_URL
  baseUrlEnvKey: string;  // e.g. 'SCANNER_1_BASE_URL' — stored on Scanner.baseUrlEnvKey
  secretEnvKey: string;   // e.g. 'SCANNER_1_SHARED_SECRET'
  baseUrl: string;
  sharedSecret: string;
}

/**
 * Scan process.env for every SCANNER_<N>_BASE_URL with a non-empty value.
 * Sorted by numeric index so logs/UI order is stable.
 */
export function discoverScannerSlots(
  env: NodeJS.ProcessEnv = process.env,
): ScannerEnvSlot[] {
  const slots: ScannerEnvSlot[] = [];
  for (const key of Object.keys(env)) {
    const match = key.match(BASE_URL_PATTERN);
    if (!match) continue;
    const baseUrl = (env[key] ?? '').trim();
    if (!baseUrl) continue;
    const index = match[1];
    const secretEnvKey = `SCANNER_${index}_SHARED_SECRET`;
    slots.push({
      index,
      baseUrlEnvKey: key,
      secretEnvKey,
      baseUrl,
      sharedSecret: (env[secretEnvKey] ?? '').trim(),
    });
  }
  return slots.sort((a, b) => Number(a.index) - Number(b.index));
}

/**
 * Look up a single slot by its baseUrlEnvKey (which is what we persist on the
 * Scanner row). Returns null if the env var is not set.
 */
export function resolveSlotByEnvKey(
  baseUrlEnvKey: string,
  env: NodeJS.ProcessEnv = process.env,
): ScannerEnvSlot | null {
  const match = baseUrlEnvKey.match(BASE_URL_PATTERN);
  if (!match) return null;
  const baseUrl = (env[baseUrlEnvKey] ?? '').trim();
  if (!baseUrl) return null;
  const index = match[1];
  const secretEnvKey = `SCANNER_${index}_SHARED_SECRET`;
  return {
    index,
    baseUrlEnvKey,
    secretEnvKey,
    baseUrl,
    sharedSecret: (env[secretEnvKey] ?? '').trim(),
  };
}
