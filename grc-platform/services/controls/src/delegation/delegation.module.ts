import { Module } from '@nestjs/common';
import { DelegationService } from './delegation.service';
import { DelegationController } from './delegation.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [DelegationService],
  controllers: [DelegationController],
  exports: [DelegationService],
})
export class DelegationModule {}
