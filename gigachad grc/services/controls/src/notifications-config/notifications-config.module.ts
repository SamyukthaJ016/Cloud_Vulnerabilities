import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsConfigController } from './notifications-config.controller';
import { NotificationsConfigService } from './notifications-config.service';
import { SlackNotificationsService } from './slack-notifications.service';
import { ConfigurableEmailService } from './configurable-email.service';

@Module({
  imports: [PrismaModule],
  controllers: [NotificationsConfigController],
  providers: [
    NotificationsConfigService,
    SlackNotificationsService,
    ConfigurableEmailService,
  ],
  exports: [
    NotificationsConfigService,
    SlackNotificationsService,
    ConfigurableEmailService,
  ],
})
export class NotificationsConfigModule {}




