import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsString, IsBoolean, IsOptional } from 'class-validator';
import { ConfigFormat } from './export-config.dto';

export class ImportConfigDto {
  @ApiProperty({
    enum: ConfigFormat,
    description: 'Format of the configuration being imported',
  })
  @IsEnum(ConfigFormat)
  format: ConfigFormat;

  @ApiProperty({
    description: 'Configuration content (YAML, JSON, or Terraform HCL)',
  })
  @IsString()
  config: string;

  @ApiPropertyOptional({
    default: false,
    description: 'If true, preview changes without applying them',
  })
  @IsOptional()
  @IsBoolean()
  dryRun?: boolean;

  @ApiPropertyOptional({
    default: false,
    description: 'Skip resources that already exist instead of updating them',
  })
  @IsOptional()
  @IsBoolean()
  skipExisting?: boolean;

  @ApiPropertyOptional({
    default: false,
    description: 'Update existing resources instead of skipping them',
  })
  @IsOptional()
  @IsBoolean()
  updateExisting?: boolean;
}

export class ImportConfigResponseDto {
  @ApiProperty({ description: 'Total resources processed' })
  total: number;

  @ApiProperty({ description: 'Number of resources created' })
  created: number;

  @ApiProperty({ description: 'Number of resources updated' })
  updated: number;

  @ApiProperty({ description: 'Number of resources skipped' })
  skipped: number;

  @ApiProperty({ description: 'Number of resources deleted' })
  deleted: number;

  @ApiProperty({ description: 'Number of errors encountered' })
  errors: number;

  @ApiProperty({
    type: 'array',
    items: { type: 'object' },
    description: 'Detailed error messages',
  })
  errorDetails: Array<{
    resourceType: string;
    resourceId?: string;
    error: string;
    line?: number;
  }>;

  @ApiProperty({ description: 'Whether this was a dry run (no changes applied)' })
  dryRun: boolean;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: 'Change plan summary (for dry run)',
  })
  plan?: {
    toCreate: number;
    toUpdate: number;
    toDelete: number;
    warnings: string[];
  };
}

