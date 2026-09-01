import { Module } from '@nestjs/common';
import { VendorsService } from './vendors.service';
import { VendorsController } from './vendors.controller';
import { VendorAIService } from '../ai/vendor-ai.service';
import { TprmConfigService } from '../config/tprm-config.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [VendorsController],
  providers: [VendorsService, VendorAIService, TprmConfigService, PrismaService, AuditService],
  exports: [VendorsService],
})
export class VendorsModule {}
