-- DropIndex
DROP INDEX IF EXISTS "Organization_domain_idx";

-- CreateIndex
CREATE UNIQUE INDEX "Organization_domain_key" ON "Organization"("domain");
