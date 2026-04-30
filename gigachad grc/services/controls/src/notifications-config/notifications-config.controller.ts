import {
  Controller,
  Get,
  Put,
  Post,
  Delete,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { NotificationsConfigService } from './notifications-config.service';
import { SlackNotificationsService } from './slack-notifications.service';
import { ConfigurableEmailService } from './configurable-email.service';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { DevAuthGuard } from '../auth/dev-auth.guard';
import {
  UpdateEmailConfigDto,
  UpdateSlackConfigDto,
  UpdateDefaultNotificationsDto,
  TestEmailDto,
  TestSlackDto,
  NotificationConfigResponseDto,
  TestResultDto,
} from './dto/notification-config.dto';

@ApiTags('Notification Configuration')
@ApiBearerAuth()
@Controller('api/notifications-config')
@UseGuards(DevAuthGuard)
export class NotificationsConfigController {
  constructor(
    private readonly configService: NotificationsConfigService,
    private readonly slackService: SlackNotificationsService,
    private readonly emailService: ConfigurableEmailService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Get notification configuration for organization' })
  @ApiResponse({ status: 200, type: NotificationConfigResponseDto })
  async getConfig(
    @CurrentUser() user: UserContext,
  ): Promise<NotificationConfigResponseDto> {
    return this.configService.getConfig(user.organizationId);
  }

  @Put('email')
  @ApiOperation({ summary: 'Update email provider configuration' })
  @ApiResponse({ status: 200, type: NotificationConfigResponseDto })
  async updateEmailConfig(
    @CurrentUser() user: UserContext,
    @Body() dto: UpdateEmailConfigDto,
  ): Promise<NotificationConfigResponseDto> {
    return this.configService.updateEmailConfig(user.organizationId, dto);
  }

  @Put('slack')
  @ApiOperation({ summary: 'Update Slack notification configuration' })
  @ApiResponse({ status: 200, type: NotificationConfigResponseDto })
  async updateSlackConfig(
    @CurrentUser() user: UserContext,
    @Body() dto: UpdateSlackConfigDto,
  ): Promise<NotificationConfigResponseDto> {
    return this.configService.updateSlackConfig(user.organizationId, dto);
  }

  @Put('defaults')
  @ApiOperation({ summary: 'Update default notification preferences' })
  @ApiResponse({ status: 200, type: NotificationConfigResponseDto })
  async updateDefaultNotifications(
    @CurrentUser() user: UserContext,
    @Body() dto: UpdateDefaultNotificationsDto,
  ): Promise<NotificationConfigResponseDto> {
    return this.configService.updateDefaultNotifications(user.organizationId, dto);
  }

  @Post('test-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send a test email to verify configuration' })
  @ApiResponse({ status: 200, type: TestResultDto })
  async testEmail(
    @CurrentUser() user: UserContext,
    @Body() dto: TestEmailDto,
  ): Promise<TestResultDto> {
    try {
      const success = await this.emailService.sendTestEmail(
        user.organizationId,
        dto.recipientEmail,
      );

      return {
        success,
        message: success
          ? `Test email sent successfully to ${dto.recipientEmail}`
          : 'Failed to send test email. Please check your configuration.',
      };
    } catch (error) {
      return {
        success: false,
        message: `Error: ${error.message}`,
      };
    }
  }

  @Post('test-slack')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send a test Slack message to verify configuration' })
  @ApiResponse({ status: 200, type: TestResultDto })
  async testSlack(
    @CurrentUser() user: UserContext,
    @Body() dto: TestSlackDto,
  ): Promise<TestResultDto> {
    try {
      const success = await this.slackService.sendTestMessage(
        user.organizationId,
        dto.channel,
      );

      return {
        success,
        message: success
          ? 'Test message sent successfully to Slack'
          : 'Failed to send test message. Please check your configuration.',
      };
    } catch (error) {
      return {
        success: false,
        message: `Error: ${error.message}`,
      };
    }
  }

  @Delete('slack')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Disconnect Slack notifications' })
  @ApiResponse({ status: 200, type: NotificationConfigResponseDto })
  async disconnectSlack(
    @CurrentUser() user: UserContext,
  ): Promise<NotificationConfigResponseDto> {
    return this.configService.disconnectSlack(user.organizationId);
  }
}

