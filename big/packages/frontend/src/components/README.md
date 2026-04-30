# components/

Generic UI primitives and app layout shells.

## Structure

```
components/
├── ui/        # shadcn/ui primitives — added via the shadcn CLI, NOT hand-written
└── layout/    # AppShell, AuthLayout, TopBar, Sidebar — app-wide layout scaffolding
```

## Rules

1. **No feature logic here.** Feature-specific components live in `features/<module>/components/`.
2. **`ui/` is copy-in, not a package.** Run `pnpm dlx shadcn-ui@latest add button` etc. from `packages/frontend/` to install primitives; they land under `ui/` as editable files.
3. **`layout/` is the only place that composes app chrome.** Route elements render their page component inside the layout's `<Outlet />` — pages never render their own sidebar/topbar.
4. **Import path convention:** `import { Button } from '@/components/ui/button'`.

## Adding a new primitive

If you need a new shadcn primitive:

```bash
cd packages/frontend
pnpm dlx shadcn-ui@latest add <primitive>   # e.g. skeleton, progress, alert-dialog
```

This writes to `components/ui/<name>.tsx`. Commit the file — it's now owned by this repo.

## What NOT to add

- A feature-specific dialog like `<RunScannerDialog>` — that lives in `features/scans/components/`.
- Feature-specific hooks — those live next to their feature's api.
- A wrapping `<Card>` that's always used for dashboard tiles — make it a layout component in `features/dashboard/` instead, since only dashboard uses it that way.
