import { Module } from '@nestjs/common';
import { FindingsService } from './findings.service';
import { FindingsController } from './findings.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [FindingsController],
  providers: [FindingsService],
  exports: [FindingsService],
})
export class FindingsModule {}





