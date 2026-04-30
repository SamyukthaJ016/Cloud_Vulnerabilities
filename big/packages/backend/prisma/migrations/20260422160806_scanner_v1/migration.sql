/*
  Warnings:

  - The values [QUEUED,PARTIAL,CANCELED] on the enum `ScanStatus` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `externalJobId` on the `ScanJob` table. All the data in the column will be lost.
  - You are about to drop the column `payload` on the `ScanJob` table. All the data in the column will be lost.
  - You are about to drop the column `retryCount` on the `ScanJob` table. All the data in the column will be lost.
  - You are about to drop the column `isActive` on the `Scanner` table. All the data in the column will be lost.
  - You are about to drop the column `requiredSecretKeys` on the `Scanner` table. All the data in the column will be lost.
  - You are about to drop the `ScannerConfig` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `credentialSchema` to the `Scanner` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "ScannerAvailability" AS ENUM ('AVAILABLE', 'UNAVAILABLE');

-- AlterEnum
BEGIN;
CREATE TYPE "ScanStatus_new" AS ENUM ('DISPATCHED', 'RUNNING', 'COMPLETED', 'FAILED');
ALTER TABLE "public"."ScanJob" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "ScanJob" ALTER COLUMN "status" TYPE "ScanStatus_new" USING ("status"::text::"ScanStatus_new");
ALTER TYPE "ScanStatus" RENAME TO "ScanStatus_old";
ALTER TYPE "ScanStatus_new" RENAME TO "ScanStatus";
DROP TYPE "public"."ScanStatus_old";
ALTER TABLE "ScanJob" ALTER COLUMN "status" SET DEFAULT 'DISPATCHED';
COMMIT;

-- DropForeignKey
ALTER TABLE "ScannerConfig" DROP CONSTRAINT "ScannerConfig_orgId_fkey";

-- DropForeignKey
ALTER TABLE "ScannerConfig" DROP CONSTRAINT "ScannerConfig_scannerId_fkey";

-- DropIndex
DROP INDEX "ScanJob_externalJobId_idx";

-- AlterTable
ALTER TABLE "ScanJob" DROP COLUMN "externalJobId",
DROP COLUMN "payload",
DROP COLUMN "retryCount",
ADD COLUMN     "externalScanId" TEXT,
ADD COLUMN     "summary" JSONB,
ADD COLUMN     "viewSecretHash" TEXT,
ALTER COLUMN "status" SET DEFAULT 'DISPATCHED';

-- AlterTable
ALTER TABLE "Scanner" DROP COLUMN "isActive",
DROP COLUMN "requiredSecretKeys",
ADD COLUMN     "availability" "ScannerAvailability" NOT NULL DEFAULT 'AVAILABLE',
ADD COLUMN     "credentialSchema" JSONB NOT NULL,
ADD COLUMN     "dashboardBaseUrl" TEXT,
ADD COLUMN     "iconUrl" TEXT,
ADD COLUMN     "lastError" TEXT,
ADD COLUMN     "manifestFetchedAt" TIMESTAMP(3);

-- DropTable
DROP TABLE "ScannerConfig";

-- CreateIndex
CREATE INDEX "ScanJob_externalScanId_idx" ON "ScanJob"("externalScanId");
