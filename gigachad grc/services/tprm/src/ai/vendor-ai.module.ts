import { Module } from '@nestjs/common';
import { VendorAIService } from './vendor-ai.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  providers: [VendorAIService, PrismaService, AuditService],
  exports: [VendorAIService],
})
export class VendorAIModule {}

