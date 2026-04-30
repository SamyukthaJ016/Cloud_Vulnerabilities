import { Module } from '@nestjs/common';
import { TrustConfigService } from './trust-config.service';
import { TrustConfigController } from './trust-config.controller';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [TrustConfigController],
  providers: [TrustConfigService, PrismaService, AuditService],
  exports: [TrustConfigService],
})
export class TrustConfigModule {}

