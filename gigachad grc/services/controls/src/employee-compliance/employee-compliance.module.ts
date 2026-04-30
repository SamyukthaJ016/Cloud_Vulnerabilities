import { Module } from '@nestjs/common';
import { EmployeeComplianceController } from './employee-compliance.controller';
import { EmployeeComplianceService } from './employee-compliance.service';
import { CorrelationService } from './correlation.service';
import { ComplianceScoreService } from './compliance-score.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [EmployeeComplianceController],
  providers: [
    EmployeeComplianceService,
    CorrelationService,
    ComplianceScoreService,
  ],
  exports: [EmployeeComplianceService, CorrelationService, ComplianceScoreService],
})
export class EmployeeComplianceModule {}




