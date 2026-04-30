# api/

Network layer. Two clients, both auth'd via the cookie set by backend on login.

## Files

- `http.ts` — axios instance. `baseURL = VITE_API_BASE_URL`. 401 redirects to `/login?next=`. All errors become `ApiError`.
- `errors.ts` — `ApiError` class + `useApiErrorToast` hook.
- `ws.ts` — Socket.IO client factory (used by `features/notifications/WebSocketProvider`).

## Feature API layer convention

Every feature owns a `features/<module>/api/<module>.api.ts` that:

1. Declares typed functions that call `http.get/post/...` and return `Promise<SomeDto>` from `@cloudguard/shared`.
2. Exports TanStack Query hooks: `useSomethingQuery`, `useCreateSomethingMutation`.
3. Keeps query keys as tuples: `['scans', orgId, { status }]`.

Example shape:

```ts
import { http } from '@/api/http';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { ScanJobDto, RunScanDto, RunScanResponse } from '@cloudguard/shared';

export function useScansQuery(filters: { status?: string } = {}) {
  return useQuery({
    queryKey: ['scans', filters],
    queryFn: async () => (await http.get<ScanJobDto[]>('/scans', { params: filters })).data,
  });
}

export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: RunScanDto) =>
      (await http.post<RunScanResponse>('/scans/run', dto)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
}
```

## Rules

1. **No raw `fetch` or bare `axios`.** Always `import { http } from '@/api/http'`.
2. **Never throw strings.** Every error is `ApiError` with `.status` + `.message`.
3. **Query keys include all params.** TanStack caches by deep-equality on the key tuple.
4. **Mutation `onSuccess` invalidates the right queries.** Use the list-level key, not the specific item.
5. **Types come from `@cloudguard/shared`.** If a type is missing there, add it in `packages/shared/` first.
