import { Module } from '@nestjs/common';
import { RiskAssessmentController } from './risk-assessment.controller';
import { RiskAssessmentService } from './risk-assessment.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [RiskAssessmentController],
  providers: [RiskAssessmentService, PrismaService, AuditService],
  exports: [RiskAssessmentService],
})
export class RiskAssessmentModule {}
