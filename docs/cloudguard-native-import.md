# Import CloudGuard findings into GRC

The GRC dashboard displays the latest completed scanner scan. Open **CloudGuard GRC** in the Compliance sidebar to review every finding and map it to framework requirements.

An administrator or compliance manager with `risk:create` permission can select **Import into Evidence and Risk Register**. The server fetches the reviewed scan from the connector configured for the authenticated organization; the browser submits only its scan ID. If a newer scan completes before submission, refresh and review the new scan first.

The import creates a downloadable JSON report in Evidence with `pending_review` status. Distinct non-informational resource/issue pairs become security risks in the `risk_identified` intake stage. Scanner `critical` severity maps to GRC's `very_high` initial risk severity; original scanner severity remains in the report. Informational findings remain in the report without creating risk tickets.

The report and risk observations reference each other through the evidence ID, risk documentation and risk history. No controls are marked implemented, evidence approved, or risks assessed automatically.

Repeated or concurrent imports do not duplicate the report, risks or observations. Later scans attach another observation to an existing matching resource/issue. Existing risk assessments, severity decisions, owners, treatment and deletions are preserved. Existing evidence is not overwritten or automatically restored after deletion.

The main dashboard's former fixed percentage scores and fixed connection labels have been replaced with live scan counts. Native GRC Evidence and Risk Register counts remain separate from the scanner's historic compliance/control observations.

## Verification

- Scanner snapshot tests cover connector identity, complete findings and absence of historical fallback.
- GRC importer tests cover tenant mismatch, changed scan selection, informational findings, idempotency, preserved treatment and deletions.
- The optional PostgreSQL test uses `CLOUDGUARD_GRC_TEST_DATABASE_URL`, restricted to a disposable localhost database whose name ends in `_regression`. It verifies concurrent imports against the real Prisma schema.
- Frontend tests cover connector navigation, latest findings, search, import permissions and evidence links.
