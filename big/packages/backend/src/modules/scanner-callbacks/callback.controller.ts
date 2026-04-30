import {
  BadRequestException,
  Controller,
  Headers,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { CallbackVerifierService } from './callback-verifier.service';
import { CallbackHandlerService, ScannerCallbackBody } from './callback-handler.service';

/**
 * Inbound callback endpoint scanners POST results to.
 * Public + HMAC-verified using the per-scanner shared secret.
 *
 * Path: POST /scanner-callbacks/:scannerKey/:jobId
 * NOTE: this controller is mounted OUTSIDE the global /api prefix (see main.ts).
 */
@Controller('scanner-callbacks')
export class CallbackController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly verifier: CallbackVerifierService,
    private readonly handler: CallbackHandlerService,
  ) {}

  @Public()
  @HttpCode(200)
  @Post(':scannerKey/:jobId')
  async handle(
    @Param('scannerKey') scannerKey: string,
    @Param('jobId') jobId: string,
    @Req() req: Request,
    @Headers('x-scanner-signature') signature: string,
    @Headers('x-scanner-nonce') nonce: string,
  ) {
    if (!signature || !nonce) {
      throw new BadRequestException('Missing signature/nonce headers');
    }
    // With `app.use('/scanner-callbacks', raw(...))` in main.ts, req.body is a Buffer.
    // Fall back to req.rawBody for safety if wiring changes.
    const reqAny = req as unknown as { body?: unknown; rawBody?: Buffer };
    const rawBody = Buffer.isBuffer(reqAny.body) ? reqAny.body : reqAny.rawBody;
    if (!rawBody) throw new BadRequestException('Raw body unavailable');

    const scanner = await this.prisma.scanner.findUnique({ where: { key: scannerKey } });
    if (!scanner) throw new NotFoundException('Unknown scanner');

    const secret = this.verifier.resolveSharedSecret(scanner.baseUrlEnvKey);
    if (!secret) throw new UnauthorizedException('Scanner secret not configured');
    if (!this.verifier.verify(rawBody, nonce, signature, secret)) {
      throw new UnauthorizedException('Invalid callback signature');
    }

    const job = await this.prisma.scanJob.findUnique({ where: { id: jobId } });
    if (!job) throw new NotFoundException('Scan job not found');
    if (job.callbackNonce !== nonce) {
      throw new UnauthorizedException('Nonce mismatch');
    }

    const body = JSON.parse(rawBody.toString('utf8')) as ScannerCallbackBody;
    await this.handler.handle(jobId, scannerKey, body);
    return { ok: true };
  }
}
