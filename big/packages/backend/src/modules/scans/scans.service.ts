import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanStatus, ScannerAvailability, Prisma } from '@prisma/client';
import { randomBytes } from 'crypto';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import type {
  RunScanResponse,
  ScanJobDto,
  ScanReportRedirectDto,
  Severity,
} from '@cloudguard/shared';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { ScannersService } from '../scanners/scanners.service';
import { resolveSlotByEnvKey } from '../scanners/scanner-env';
import { DynamicScannerClient } from '../scanner-clients/dynamic-scanner.client';

const ajv = new Ajv({ allErrors: true, removeAdditional: false, strict: false });
addFormats(ajv);

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly scanners: ScannersService,
    private readonly client: DynamicScannerClient,
  ) {}

  async requestRun(input: {
    orgId: string;
    userId: string;
    scannerKey: string;
    credentials: Record<string, unknown>;
  }): Promise<RunScanResponse> {
    const scanner = await this.scanners.getByKey(input.scannerKey);
    if (scanner.availability !== ScannerAvailability.AVAILABLE) {
      throw new ConflictException(`Scanner ${scanner.key} is unavailable`);
    }

    const validate = ajv.compile(scanner.credentialSchema as object);
    if (!validate(input.credentials)) {
      throw new BadRequestException({
        message: 'Invalid credentials for scanner',
        errors: validate.errors,
      });
    }

    const { baseUrl, sharedSecret } = this.resolveScannerEnv(scanner.baseUrlEnvKey);
    const callbackBaseUrl = this.config.get<string>('scanners.callbackBaseUrl');
    if (!callbackBaseUrl) throw new Error('SCANNER_CALLBACK_BASE_URL not configured');

    const job = await this.prisma.scanJob.create({
      data: {
        orgId: input.orgId,
        scannerId: scanner.id,
        triggeredById: input.userId,
        status: ScanStatus.DISPATCHED,
        callbackNonce: randomBytes(16).toString('hex'),
        startedAt: new Date(),
      },
    });

    try {
      const ack = await this.client.run(baseUrl, sharedSecret, {
        jobId: job.id,
        orgId: input.orgId,
        callbackUrl: `${callbackBaseUrl}/scanner-callbacks/${scanner.key}/${job.id}`,
        nonce: job.callbackNonce!,
        credentials: input.credentials,
      });
      await this.prisma.scanJob.update({
        where: { id: job.id },
        data: { externalScanId: ack.scanId },
      });
      return { jobId: job.id };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.error(`Dispatch to ${scanner.key} failed: ${message}`);
      await this.prisma.scanJob.update({
        where: { id: job.id },
        data: {
          status: ScanStatus.FAILED,
          error: message,
          completedAt: new Date(),
        },
      });
      throw new ConflictException(`Failed to dispatch scan: ${message}`);
    }
  }

  async getById(orgId: string, jobId: string): Promise<ScanJobDto> {
    const job = await this.prisma.scanJob.findFirst({
      where: { id: jobId, orgId },
      include: { scanner: true, triggeredBy: true },
    });
    if (!job) throw new NotFoundException('Scan not found');
    return toScanJobDto(job);
  }

  async listForOrg(
    orgId: string,
    params: { scannerKey?: string; status?: string },
  ): Promise<ScanJobDto[]> {
    const where: Prisma.ScanJobWhereInput = { orgId };
    if (params.status) where.status = params.status as ScanStatus;
    if (params.scannerKey) where.scanner = { key: params.scannerKey };

    const jobs = await this.prisma.scanJob.findMany({
      where,
      orderBy: { queuedAt: 'desc' },
      include: { scanner: true, triggeredBy: true },
    });
    return jobs.map(toScanJobDto);
  }

  async getReportRedirect(orgId: string, jobId: string): Promise<ScanReportRedirectDto> {
    const job = await this.prisma.scanJob.findFirst({
      where: { id: jobId, orgId },
      include: { scanner: true },
    });
    if (!job) throw new NotFoundException('Scan not found');
    if (job.status !== ScanStatus.COMPLETED) {
      throw new ConflictException('Scan is not completed yet');
    }
    if (job.scanner.key === 'cloud' && job.externalScanId) {
      const baseUrl =
        this.config.get<string>('cloudguard.baseUrl') ||
        'https://cloud-vulnerabilities.vercel.app';
      const url = new URL(`${baseUrl}/dashboard`);
      url.searchParams.set('scanIds', job.externalScanId);
      return { redirectUrl: url.toString() };
    }
    if (!job.externalScanId || !job.scanner.dashboardBaseUrl) {
      throw new ConflictException('Scan has no dashboard URL');
    }

    const { baseUrl, sharedSecret } = this.resolveScannerEnv(job.scanner.baseUrlEnvKey);
    const { viewSecret } = await this.client.fetchViewToken(
      baseUrl,
      sharedSecret,
      job.externalScanId,
    );

    const url = new URL(job.scanner.dashboardBaseUrl);
    url.searchParams.set('scanId', job.externalScanId);
    url.searchParams.set('secret', viewSecret);
    return { redirectUrl: url.toString() };
  }

  private resolveScannerEnv(baseUrlEnvKey: string): { baseUrl: string; sharedSecret: string } {
    const slot = resolveSlotByEnvKey(baseUrlEnvKey);
    if (!slot) throw new Error(`Scanner ${baseUrlEnvKey} not configured`);
    if (!slot.sharedSecret) {
      throw new Error(`${slot.secretEnvKey} is empty — required for HMAC signing`);
    }
    return { baseUrl: slot.baseUrl, sharedSecret: slot.sharedSecret };
  }
}

function toScanJobDto(job: {
  id: string;
  status: ScanStatus;
  queuedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  error: string | null;
  externalScanId: string | null;
  summary: Prisma.JsonValue | null;
  scanner: { key: string };
  triggeredBy: { id: string; name: string | null; email: string };
}): ScanJobDto {
  return {
    id: job.id,
    scannerKey: job.scanner.key,
    status: job.status,
    queuedAt: job.queuedAt.toISOString(),
    startedAt: job.startedAt?.toISOString() ?? null,
    completedAt: job.completedAt?.toISOString() ?? null,
    error: job.error,
    externalScanId: job.externalScanId,
    summary: (job.summary as Record<Severity, number> | null) ?? null,
    triggeredBy: {
      id: job.triggeredBy.id,
      name: job.triggeredBy.name,
      email: job.triggeredBy.email,
    },
  };
}
