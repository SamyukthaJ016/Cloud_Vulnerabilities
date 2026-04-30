import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsBoolean,
  IsEnum,
  IsArray,
  IsNumber,
  IsDateString,
  ValidateNested,
  Min,
  Max,
  IsEmail,
} from 'class-validator';
import { Type } from 'class-transformer';

// ============================================
// Enums
// ============================================

export enum CampaignStatus {
  DRAFT = 'draft',
  SCHEDULED = 'scheduled',
  ACTIVE = 'active',
  PAUSED = 'paused',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
}

export enum PhishingTemplateType {
  CREDENTIAL_HARVEST = 'credential_harvest',
  MALICIOUS_ATTACHMENT = 'malicious_attachment',
  LINK_CLICK = 'link_click',
  DATA_ENTRY = 'data_entry',
  REPLY = 'reply',
}

export enum DifficultyLevel {
  EASY = 'easy',
  MEDIUM = 'medium',
  HARD = 'hard',
  EXPERT = 'expert',
}

export enum EmailProvider {
  SENDGRID = 'sendgrid',
  SES = 'ses',
  SMTP = 'smtp',
}

// ============================================
// Template DTOs
// ============================================

export class PhishingTemplateDto {
  @ApiProperty({ description: 'Template ID' })
  id: string;

  @ApiProperty({ description: 'Template name' })
  name: string;

  @ApiProperty({ description: 'Template description' })
  description: string;

  @ApiProperty({ enum: PhishingTemplateType, description: 'Type of phishing simulation' })
  type: PhishingTemplateType;

  @ApiProperty({ enum: DifficultyLevel, description: 'Difficulty level' })
  difficulty: DifficultyLevel;

  @ApiProperty({ description: 'Email subject line' })
  subject: string;

  @ApiProperty({ description: 'Sender display name' })
  senderName: string;

  @ApiProperty({ description: 'Sender email address' })
  senderEmail: string;

  @ApiProperty({ description: 'HTML email body' })
  htmlBody: string;

  @ApiProperty({ description: 'Plain text email body' })
  textBody: string;

  @ApiPropertyOptional({ description: 'Landing page HTML (for credential harvest)' })
  landingPageHtml?: string;

  @ApiProperty({ description: 'Red flags/indicators for training' })
  redFlags: string[];

  @ApiProperty({ description: 'Tags for categorization' })
  tags: string[];

  @ApiProperty({ description: 'Whether template is active' })
  isActive: boolean;

  @ApiProperty({ description: 'Created at' })
  createdAt: Date;
}

export class CreatePhishingTemplateDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty()
  @IsString()
  description: string;

  @ApiProperty({ enum: PhishingTemplateType })
  @IsEnum(PhishingTemplateType)
  type: PhishingTemplateType;

  @ApiProperty({ enum: DifficultyLevel })
  @IsEnum(DifficultyLevel)
  difficulty: DifficultyLevel;

  @ApiProperty()
  @IsString()
  subject: string;

  @ApiProperty()
  @IsString()
  senderName: string;

  @ApiProperty()
  @IsEmail()
  senderEmail: string;

  @ApiProperty()
  @IsString()
  htmlBody: string;

  @ApiProperty()
  @IsString()
  textBody: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  landingPageHtml?: string;

  @ApiProperty()
  @IsArray()
  @IsString({ each: true })
  redFlags: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}

// ============================================
// Campaign DTOs
// ============================================

export class CampaignTargetDto {
  @ApiProperty()
  @IsString()
  userId: string;

  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  department?: string;
}

export class CreateCampaignDto {
  @ApiProperty({ description: 'Campaign name' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'Campaign description' })
  @IsString()
  description: string;

  @ApiProperty({ description: 'Template ID to use' })
  @IsString()
  templateId: string;

  @ApiProperty({ description: 'Target users', type: [CampaignTargetDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CampaignTargetDto)
  targets: CampaignTargetDto[];

  @ApiPropertyOptional({ description: 'Scheduled start time' })
  @IsOptional()
  @IsDateString()
  scheduledAt?: string;

  @ApiPropertyOptional({ description: 'End time for campaign' })
  @IsOptional()
  @IsDateString()
  endsAt?: string;

  @ApiPropertyOptional({ description: 'Send emails randomly over time window (hours)' })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(168)
  spreadOverHours?: number;

  @ApiPropertyOptional({ description: 'Training module to assign on failure' })
  @IsOptional()
  @IsString()
  failureTrainingId?: string;

  @ApiPropertyOptional({ description: 'Send report notification email after completion' })
  @IsOptional()
  @IsBoolean()
  sendReportEmail?: boolean;

  @ApiPropertyOptional({ description: 'Report recipient email addresses' })
  @IsOptional()
  @IsArray()
  @IsEmail({}, { each: true })
  reportRecipients?: string[];
}

export class CampaignDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  description: string;

  @ApiProperty()
  templateId: string;

  @ApiProperty({ enum: CampaignStatus })
  status: CampaignStatus;

  @ApiProperty()
  targetCount: number;

  @ApiProperty()
  sentCount: number;

  @ApiProperty()
  openedCount: number;

  @ApiProperty()
  clickedCount: number;

  @ApiProperty()
  reportedCount: number;

  @ApiProperty()
  credentialsEnteredCount: number;

  @ApiPropertyOptional()
  scheduledAt?: Date;

  @ApiPropertyOptional()
  startedAt?: Date;

  @ApiPropertyOptional()
  completedAt?: Date;

  @ApiProperty()
  createdAt: Date;
}

// ============================================
// Campaign Result DTOs
// ============================================

export enum TargetStatus {
  PENDING = 'pending',
  SENT = 'sent',
  DELIVERED = 'delivered',
  OPENED = 'opened',
  CLICKED = 'clicked',
  CREDENTIALS_ENTERED = 'credentials_entered',
  REPORTED = 'reported',
  BOUNCED = 'bounced',
}

export class CampaignTargetResultDto {
  @ApiProperty()
  userId: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  name?: string;

  @ApiProperty({ enum: TargetStatus })
  status: TargetStatus;

  @ApiProperty()
  sentAt?: Date;

  @ApiProperty()
  openedAt?: Date;

  @ApiProperty()
  clickedAt?: Date;

  @ApiProperty()
  reportedAt?: Date;

  @ApiProperty()
  credentialsEnteredAt?: Date;

  @ApiProperty()
  trainingAssigned: boolean;

  @ApiProperty()
  trainingCompleted: boolean;
}

export class CampaignResultsDto {
  @ApiProperty()
  campaign: CampaignDto;

  @ApiProperty({ type: [CampaignTargetResultDto] })
  targets: CampaignTargetResultDto[];

  @ApiProperty()
  metrics: {
    totalTargets: number;
    emailsSent: number;
    emailsDelivered: number;
    emailsOpened: number;
    linksClicked: number;
    credentialsEntered: number;
    reported: number;
    bounced: number;
    openRate: number;
    clickRate: number;
    reportRate: number;
    failureRate: number;
  };

  @ApiProperty()
  departmentBreakdown: Array<{
    department: string;
    targetCount: number;
    clickedCount: number;
    clickRate: number;
  }>;
}

// ============================================
// Email Configuration DTO
// ============================================

export class PhishingEmailConfigDto {
  @ApiProperty({ enum: EmailProvider })
  @IsEnum(EmailProvider)
  provider: EmailProvider;

  @ApiPropertyOptional({ description: 'SendGrid API key' })
  @IsOptional()
  @IsString()
  sendgridApiKey?: string;

  @ApiPropertyOptional({ description: 'AWS SES region' })
  @IsOptional()
  @IsString()
  sesRegion?: string;

  @ApiPropertyOptional({ description: 'SMTP host' })
  @IsOptional()
  @IsString()
  smtpHost?: string;

  @ApiPropertyOptional({ description: 'SMTP port' })
  @IsOptional()
  @IsNumber()
  smtpPort?: number;

  @ApiPropertyOptional({ description: 'SMTP username' })
  @IsOptional()
  @IsString()
  smtpUsername?: string;

  @ApiPropertyOptional({ description: 'SMTP password' })
  @IsOptional()
  @IsString()
  smtpPassword?: string;

  @ApiProperty({ description: 'Tracking domain for click tracking' })
  @IsString()
  trackingDomain: string;

  @ApiProperty({ description: 'Landing page domain' })
  @IsString()
  landingPageDomain: string;
}

// ============================================
// Report Email Event DTO
// ============================================

export class ReportPhishingDto {
  @ApiProperty({ description: 'Tracking token from email' })
  @IsString()
  trackingToken: string;

  @ApiPropertyOptional({ description: 'Additional notes from reporter' })
  @IsOptional()
  @IsString()
  notes?: string;
}

