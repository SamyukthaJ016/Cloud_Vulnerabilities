import { Injectable, Logger } from '@nestjs/common';
import { NotificationsConfigService } from './notifications-config.service';

export interface SlackMessage {
  channel?: string;
  text: string;
  blocks?: SlackBlock[];
  attachments?: SlackAttachment[];
}

export interface SlackBlock {
  type: string;
  text?: {
    type: string;
    text: string;
    emoji?: boolean;
  };
  elements?: any[];
  accessory?: any;
}

export interface SlackAttachment {
  color?: string;
  title?: string;
  text?: string;
  fields?: { title: string; value: string; short?: boolean }[];
  footer?: string;
  ts?: number;
}

@Injectable()
export class SlackNotificationsService {
  private readonly logger = new Logger(SlackNotificationsService.name);

  constructor(private configService: NotificationsConfigService) {}

  /**
   * Send a message to Slack using the organization's configuration
   */
  async sendMessage(
    organizationId: string,
    message: SlackMessage,
  ): Promise<boolean> {
    const config = await this.configService.getRawConfig(organizationId);

    if (!config || !config.slackNotificationsEnabled) {
      this.logger.debug(`Slack notifications disabled for org ${organizationId}`);
      return false;
    }

    const channel = message.channel || config.slackDefaultChannel;

    // Try webhook first, then bot token
    if (config.slackWebhookUrl) {
      return this.sendViaWebhook(config.slackWebhookUrl, message);
    } else if (config.slackBotToken) {
      return this.sendViaBotToken(config.slackBotToken, channel, message);
    }

    this.logger.warn(`No Slack credentials configured for org ${organizationId}`);
    return false;
  }

  /**
   * Send message via incoming webhook
   */
  private async sendViaWebhook(
    webhookUrl: string,
    message: SlackMessage,
  ): Promise<boolean> {
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text: message.text,
          blocks: message.blocks,
          attachments: message.attachments,
        }),
      });

      if (response.ok) {
        this.logger.debug('Slack message sent via webhook');
        return true;
      } else {
        const error = await response.text();
        this.logger.error(`Slack webhook error: ${error}`);
        return false;
      }
    } catch (error) {
      this.logger.error(`Failed to send Slack webhook: ${error.message}`);
      return false;
    }
  }

  /**
   * Send message via bot token (Slack Web API)
   */
  private async sendViaBotToken(
    botToken: string,
    channel: string | null,
    message: SlackMessage,
  ): Promise<boolean> {
    if (!channel) {
      this.logger.error('No channel specified for Slack bot message');
      return false;
    }

    try {
      const response = await fetch('https://slack.com/api/chat.postMessage', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${botToken}`,
        },
        body: JSON.stringify({
          channel,
          text: message.text,
          blocks: message.blocks,
          attachments: message.attachments,
        }),
      });

      const result = await response.json();

      if (result.ok) {
        this.logger.debug(`Slack message sent to channel ${channel}`);
        return true;
      } else {
        this.logger.error(`Slack API error: ${result.error}`);
        return false;
      }
    } catch (error) {
      this.logger.error(`Failed to send Slack message: ${error.message}`);
      return false;
    }
  }

  /**
   * Send a test message to verify configuration
   */
  async sendTestMessage(
    organizationId: string,
    channel?: string,
  ): Promise<boolean> {
    const testMessage: SlackMessage = {
      channel,
      text: '🎉 GigaChad GRC Test Message',
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: '🎉 Test Message from GigaChad GRC',
            emoji: true,
          },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: 'Your Slack notifications are configured correctly! You will receive compliance alerts, evidence reminders, and other important notifications here.',
          },
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: `Sent at: ${new Date().toISOString()}`,
            },
          ],
        },
      ],
    };

    return this.sendMessage(organizationId, testMessage);
  }

  /**
   * Send a compliance drift alert
   */
  async sendComplianceDriftAlert(
    organizationId: string,
    controlName: string,
    frameworkName: string,
    previousStatus: string,
    newStatus: string,
    channel?: string,
  ): Promise<boolean> {
    const statusColor = newStatus === 'compliant' ? '#36a64f' : '#e74c3c';
    const emoji = newStatus === 'compliant' ? '✅' : '⚠️';

    const message: SlackMessage = {
      channel,
      text: `${emoji} Compliance Status Changed: ${controlName}`,
      attachments: [
        {
          color: statusColor,
          title: `${emoji} Control Status Changed`,
          fields: [
            { title: 'Control', value: controlName, short: true },
            { title: 'Framework', value: frameworkName, short: true },
            { title: 'Previous Status', value: previousStatus, short: true },
            { title: 'New Status', value: newStatus, short: true },
          ],
          footer: 'GigaChad GRC',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    return this.sendMessage(organizationId, message);
  }

  /**
   * Send an evidence expiring alert
   */
  async sendEvidenceExpiringAlert(
    organizationId: string,
    evidenceName: string,
    controlName: string,
    expiresAt: Date,
    daysUntilExpiry: number,
    channel?: string,
  ): Promise<boolean> {
    const urgencyColor = daysUntilExpiry <= 7 ? '#e74c3c' : '#f39c12';
    const emoji = daysUntilExpiry <= 7 ? '🚨' : '⏰';

    const message: SlackMessage = {
      channel,
      text: `${emoji} Evidence Expiring: ${evidenceName}`,
      attachments: [
        {
          color: urgencyColor,
          title: `${emoji} Evidence Expiring Soon`,
          fields: [
            { title: 'Evidence', value: evidenceName, short: true },
            { title: 'Control', value: controlName, short: true },
            { title: 'Expires', value: expiresAt.toLocaleDateString(), short: true },
            { title: 'Days Remaining', value: daysUntilExpiry.toString(), short: true },
          ],
          footer: 'GigaChad GRC',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    return this.sendMessage(organizationId, message);
  }

  /**
   * Send a task assigned notification
   */
  async sendTaskAssignedAlert(
    organizationId: string,
    taskTitle: string,
    assigneeName: string,
    dueDate: Date | null,
    priority: string,
    channel?: string,
  ): Promise<boolean> {
    const priorityColor = priority === 'high' ? '#e74c3c' : priority === 'medium' ? '#f39c12' : '#36a64f';

    const message: SlackMessage = {
      channel,
      text: `📋 New Task Assigned: ${taskTitle}`,
      attachments: [
        {
          color: priorityColor,
          title: '📋 New Task Assigned',
          fields: [
            { title: 'Task', value: taskTitle, short: false },
            { title: 'Assigned To', value: assigneeName, short: true },
            { title: 'Priority', value: priority.toUpperCase(), short: true },
            ...(dueDate ? [{ title: 'Due Date', value: dueDate.toLocaleDateString(), short: true }] : []),
          ],
          footer: 'GigaChad GRC',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    return this.sendMessage(organizationId, message);
  }
}




