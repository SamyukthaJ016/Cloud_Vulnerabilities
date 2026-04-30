import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ScanStatus } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../infra/prisma/prisma.service';

const BCRYPT_ROUNDS = 10;

export interface ScannerCallbackBody {
  status: 'running' | 'completed' | 'failed';
  viewSecret?: string;
  summary?: Record<string, number>;
  error?: string;
}

/**
 * Applies a verified scanner callback to the ScanJob.
 * Idempotent: callbacks for an already-terminal job are no-ops.
 */
@Injectable()
export class CallbackHandlerService {
  private readonly logger = new Logger(CallbackHandlerService.name);

  constructor(private readonly prisma: PrismaService) {}

  async handle(jobId: string, scannerKey: string, body: ScannerCallbackBody) {
    const job = await this.prisma.scanJob.findUnique({
      where: { id: jobId },
      include: { scanner: true },
    });
    if (!job) throw new NotFoundException('Scan job not found');
    if (job.scanner.key !== scannerKey) {
      throw new NotFoundException('Scan job does not belong to this scanner');
    }

    if (job.status === ScanStatus.COMPLETED || job.status === ScanStatus.FAILED) {
      this.logger.log(`Ignoring callback for terminal job ${jobId} (status=${job.status})`);
      return;
    }

    const nextStatus = mapStatus(body.status);

    const data: Parameters<typeof this.prisma.scanJob.update>[0]['data'] = {
      status: nextStatus,
    };
    if (nextStatus === ScanStatus.RUNNING && !job.startedAt) {
      data.startedAt = new Date();
    }
    if (nextStatus === ScanStatus.COMPLETED || nextStatus === ScanStatus.FAILED) {
      data.completedAt = new Date();
    }
    if (body.summary) data.summary = body.summary;
    if (body.error) data.error = body.error;
    if (body.viewSecret && nextStatus === ScanStatus.COMPLETED) {
      data.viewSecretHash = await bcrypt.hash(body.viewSecret, BCRYPT_ROUNDS);
    }

    await this.prisma.scanJob.update({ where: { id: jobId }, data });
  }
}

function mapStatus(s: ScannerCallbackBody['status']): ScanStatus {
  switch (s) {
    case 'running':
      return ScanStatus.RUNNING;
    case 'completed':
      return ScanStatus.COMPLETED;
    case 'failed':
      return ScanStatus.FAILED;
  }
}
