import { Module } from '@nestjs/common';
import { TrustAiService } from './trust-ai.service';
import { TrustAiController } from './trust-ai.controller';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [TrustAiController],
  providers: [TrustAiService, PrismaService, AuditService],
  exports: [TrustAiService],
})
export class TrustAiModule {}

