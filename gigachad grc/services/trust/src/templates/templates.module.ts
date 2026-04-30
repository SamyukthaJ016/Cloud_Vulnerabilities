import { Module } from '@nestjs/common';
import { TemplatesService } from './templates.service';
import { TemplatesController } from './templates.controller';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [TemplatesController],
  providers: [TemplatesService, PrismaService, AuditService],
  exports: [TemplatesService],
})
export class TemplatesModule {}

