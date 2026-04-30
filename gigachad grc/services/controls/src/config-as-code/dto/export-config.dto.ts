import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsArray, IsOptional, IsString } from 'class-validator';

export enum ConfigFormat {
  YAML = 'yaml',
  JSON = 'json',
  TERRAFORM = 'terraform',
}

export enum ResourceType {
  CONTROLS = 'controls',
  FRAMEWORKS = 'frameworks',
  POLICIES = 'policies',
  RISKS = 'risks',
  EVIDENCE = 'evidence',
  VENDORS = 'vendors',
}

export class ExportConfigDto {
  @ApiProperty({
    enum: ConfigFormat,
    description: 'Output format for the configuration',
    default: ConfigFormat.YAML,
  })
  @IsEnum(ConfigFormat)
  format: ConfigFormat;

  @ApiPropertyOptional({
    type: [String],
    enum: ResourceType,
    description: 'Resource types to include in export. If not specified, all resources are exported.',
    default: Object.values(ResourceType),
  })
  @IsOptional()
  @IsArray()
  @IsEnum(ResourceType, { each: true })
  resources?: ResourceType[];

  @ApiPropertyOptional({
    description: 'Workspace ID to filter resources (if multi-workspace enabled)',
  })
  @IsOptional()
  @IsString()
  workspaceId?: string;
}

export class ExportConfigResponseDto {
  @ApiProperty({ description: 'Configuration content' })
  content: string;

  @ApiProperty({ enum: ConfigFormat, description: 'Format of the exported configuration' })
  format: ConfigFormat;

  @ApiProperty({ description: 'MIME type for the exported file' })
  mimeType: string;

  @ApiProperty({ description: 'Suggested filename' })
  filename: string;

  @ApiProperty({ description: 'Number of resources exported' })
  resourceCount: number;

  @ApiProperty({ description: 'Breakdown of exported resources by type' })
  resourceBreakdown: Record<string, number>;
}

