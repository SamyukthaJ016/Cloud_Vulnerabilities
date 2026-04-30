import { Module } from '@nestjs/common';
import { CustomDashboardsController } from './custom-dashboards.controller';
import { CustomDashboardsService } from './custom-dashboards.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [CustomDashboardsController],
  providers: [CustomDashboardsService],
  exports: [CustomDashboardsService],
})
export class CustomDashboardsModule {}




