import {
  BadRequestException,
  Controller,
  Headers,
  HttpCode,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { SignatureVerifierService } from './signature-verifier.service';
import { WebhookProcessorService } from './webhook-processor.service';

@Controller('webhooks/razorpay')
export class BillingWebhooksController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly verifier: SignatureVerifierService,
    private readonly processor: WebhookProcessorService,
  ) {}

  /**
   * Flow nodes BF → BH → BI → BL.
   *   BF — gateway posts here
   *   BG — verify HMAC signature over raw body
   *   BH — ensure event.id not already processed (replay protection)
   *   BI → BL — persist + update subscription + audit
   */
  @Public()
  @HttpCode(200)
  @Post()
  async handle(@Req() req: Request, @Headers('x-razorpay-signature') signature: string) {
    if (!signature) throw new BadRequestException('Missing signature');

    // `raw` body parser is registered in main.ts for this route
    const rawBody = (req as unknown as { rawBody?: Buffer }).rawBody;
    if (!rawBody) throw new BadRequestException('Raw body unavailable');

    if (!this.verifier.verify(rawBody, signature)) {
      // flow BH1: reject + alert/log
      throw new UnauthorizedException('Invalid signature');
    }

    const body = JSON.parse(rawBody.toString('utf8')) as {
      id: string;
      event: string;
      payload: unknown;
    };

    // TODO: idempotency — prisma.webhookEvent.create({ ... }) with unique(eventId)
    //       on unique constraint violation, return 200 (already processed).
    await this.processor.process(body);
    return { ok: true };
  }
}
