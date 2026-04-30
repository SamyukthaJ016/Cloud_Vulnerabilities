import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

/**
 * Flow node N1A: store raw artifacts / evidence.
 * Artifacts are the opaque scanner output (logs, full JSON reports, screenshots).
 * They live in object storage (S3 / compatible). DB stores only the URL + checksum.
 */
@Injectable()
export class ArtifactsService {
  constructor(private readonly prisma: PrismaService) {}

  async store(_scanJobId: string, _artifacts: Array<{
    kind: string;
    url?: string;       // already uploaded by scanner? then just record
    contents?: Buffer;  // OR upload ourselves
    checksum?: string;
    sizeBytes?: number;
  }>) {
    // TODO:
    //   - if `contents` present, upload to S3 and compute URL + checksum
    //   - create ScanArtifact row
  }
}
