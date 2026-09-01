import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsEnum, IsInt, Min, Max, IsBoolean } from 'class-validator';
import { Type } from 'class-transformer';

export enum RetentionEntityType {
  AUDIT_LOGS = 'audit_logs',
  EVIDENCE = 'evidence',
  POLICY_VERSIONS = 'policy_versions',
  NOTIFICATIONS = 'notifications',
  TASKS = 'tasks',
  EXPORT_JOBS = 'export_jobs',
}

export enum RetentionAction {
  ARCHIVE = 'archive',
  DELETE = 'delete',
}

export enum RetentionPolicyStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  DRAFT = 'draft',
}

export class CreateRetentionPolicyDto {
  @ApiProperty({ description: 'Policy name' })
  @IsString()
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({ enum: RetentionEntityType })
  @IsEnum(RetentionEntityType)
  entityType: RetentionEntityType;

  @ApiProperty({ description: 'Retention period in days', minimum: 1, maximum: 3650 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(3650) // Max 10 years
  retentionDays: number;

  @ApiPropertyOptional({ enum: RetentionAction, default: RetentionAction.ARCHIVE })
  @IsOptional()
  @IsEnum(RetentionAction)
  action?: RetentionAction = RetentionAction.ARCHIVE;

  @ApiPropertyOptional({ enum: RetentionPolicyStatus, default: RetentionPolicyStatus.DRAFT })
  @IsOptional()
  @IsEnum(RetentionPolicyStatus)
  status?: RetentionPolicyStatus = RetentionPolicyStatus.DRAFT;
}

export class UpdateRetentionPolicyDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(3650)
  retentionDays?: number;

  @ApiPropertyOptional({ enum: RetentionAction })
  @IsOptional()
  @IsEnum(RetentionAction)
  action?: RetentionAction;

  @ApiPropertyOptional({ enum: RetentionPolicyStatus })
  @IsOptional()
  @IsEnum(RetentionPolicyStatus)
  status?: RetentionPolicyStatus;
}

export class RetentionPolicyDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiProperty({ enum: RetentionEntityType })
  entityType: RetentionEntityType;

  @ApiProperty()
  retentionDays: number;

  @ApiProperty({ enum: RetentionAction })
  action: RetentionAction;

  @ApiProperty({ enum: RetentionPolicyStatus })
  status: RetentionPolicyStatus;

  @ApiPropertyOptional()
  lastRunAt?: Date;

  @ApiPropertyOptional()
  nextRunAt?: Date;

  @ApiPropertyOptional()
  lastRunRecordsProcessed?: number;

  @ApiProperty()
  createdBy: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}

export class RetentionPolicyListQueryDto {
  @ApiPropertyOptional({ enum: RetentionEntityType })
  @IsOptional()
  @IsEnum(RetentionEntityType)
  entityType?: RetentionEntityType;

  @ApiPropertyOptional({ enum: RetentionPolicyStatus })
  @IsOptional()
  @IsEnum(RetentionPolicyStatus)
  status?: RetentionPolicyStatus;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({ default: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}

export class RunRetentionPolicyDto {
  @ApiPropertyOptional({ description: 'Dry run - show what would be affected without taking action' })
  @IsOptional()
  @IsBoolean()
  dryRun?: boolean = true;
}

export class RetentionRunResultDto {
  @ApiProperty()
  policyId: string;

  @ApiProperty()
  policyName: string;

  @ApiProperty({ enum: RetentionEntityType })
  entityType: RetentionEntityType;

  @ApiProperty({ enum: RetentionAction })
  action: RetentionAction;

  @ApiProperty()
  recordsFound: number;

  @ApiProperty()
  recordsProcessed: number;

  @ApiProperty()
  dryRun: boolean;

  @ApiProperty()
  executedAt: Date;

  @ApiPropertyOptional()
  error?: string;
}
