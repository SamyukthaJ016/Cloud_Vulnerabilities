import { Module } from '@nestjs/common';
import { TrainingController } from './training.controller';
import { TrainingService } from './training.service';
import { PrismaModule } from '../prisma/prisma.module';
import { PhishingModule } from './phishing/phishing.module';

@Module({
  imports: [PrismaModule, PhishingModule],
  controllers: [TrainingController],
  providers: [TrainingService],
  exports: [TrainingService],
})
export class TrainingModule {}
