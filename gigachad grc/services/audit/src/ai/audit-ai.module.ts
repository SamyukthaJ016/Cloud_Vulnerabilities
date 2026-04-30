import { Module } from '@nestjs/common';
import { AuditAIController } from './audit-ai.controller';
import { AuditAIService } from './audit-ai.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AuditAIController],
  providers: [AuditAIService],
  exports: [AuditAIService],
})
export class AuditAIModule {}

