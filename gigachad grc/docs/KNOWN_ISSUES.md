# Known Issues

This document tracks known issues and technical debt in the GigaChad GRC platform.

## Deprecation Warnings in Dependencies

During `npm install`, you may see deprecation warnings for the following packages:

### Affected Packages

| Package | Version | Warning | Root Cause |
|---------|---------|---------|------------|
| `glob` | 7.2.3 | Versions prior to v9 are no longer supported | Used by Jest 29, ESLint 8, exceljs |
| `lodash.isequal` | 4.5.0 | Deprecated, use `require('node:util').isDeepStrictEqual` | Used by exceljs → fast-csv |
| `fstream` | 1.0.12 | No longer supported | Used by exceljs → unzipper |
| `rimraf` | 2.7.1 | Versions prior to v4 are no longer supported | Used by exceljs → unzipper → fstream |

### Impact

- **Severity**: Low
- **Functionality**: Not affected - all packages work correctly
- **Security**: No known vulnerabilities associated with these deprecations

### Resolution Plan

These are transitive dependencies that will be resolved when upstream packages update:

1. **Jest 29 → 30**: Major version upgrade required; planned for v1.1
2. **ESLint 8 → 9**: Requires migration to flat config format; planned for v1.1
3. **exceljs**: Waiting for upstream to update `unzipper` and `fast-csv` dependencies

### Workaround

No action required. These warnings are informational and do not affect the build or functionality.

---

## Large Chunk Warning in Frontend Build

During frontend build, you may see:

```
(!) Some chunks are larger than 500 kB after minification
```

### Impact

- **Severity**: Low (performance optimization opportunity)
- **Functionality**: Not affected

### Resolution Plan

Planned optimizations for v1.1:
- [ ] Code-split the `vendor-misc` chunk
- [ ] Lazy load integration types
- [ ] Tree-shake unused chart libraries

---

*Last updated: December 2024*

