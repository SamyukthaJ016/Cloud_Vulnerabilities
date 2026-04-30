import { Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { OrganizationsModule } from '../organizations/organizations.module';
import { SubscriptionsModule } from '../subscriptions/subscriptions.module';
import { ScannersModule } from '../scanners/scanners.module';
import { SecretsModule } from '../secrets/secrets.module';
import { FindingsModule } from '../findings/findings.module';

@Module({
  imports: [OrganizationsModule, SubscriptionsModule, ScannersModule, SecretsModule, FindingsModule],
  controllers: [DashboardController],
  providers: [DashboardService],
})
export class DashboardModule {}
