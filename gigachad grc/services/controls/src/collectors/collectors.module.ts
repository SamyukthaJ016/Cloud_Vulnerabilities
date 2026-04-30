import { Module } from '@nestjs/common';
import { makeCounterProvider } from '@willsoto/nestjs-prometheus';
import { CollectorsController } from './collectors.controller';
import { CollectorsService } from './collectors.service';
import { CollectorsScheduler } from './collectors.scheduler';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [CollectorsController],
  providers: [
    CollectorsService,
    CollectorsScheduler,
    // Metrics: track collector run outcomes for monitoring/alerting
    makeCounterProvider({
      name: 'collectors_runs_total',
      help: 'Total number of collector runs grouped by status',
      labelNames: ['status'],
    }),
  ],
  exports: [CollectorsService],
})
export class CollectorsModule {}

