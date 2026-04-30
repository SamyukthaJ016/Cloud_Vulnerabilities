import { Module } from '@nestjs/common';
import { RemediationController } from './remediation.controller';
import { RemediationService } from './remediation.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [RemediationController],
  providers: [RemediationService],
  exports: [RemediationService],
})
export class RemediationModule {}

