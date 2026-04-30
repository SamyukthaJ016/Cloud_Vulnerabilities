import { IsString, IsOptional, IsArray, IsBoolean, ValidateNested } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class ChecklistItemDto {
  @ApiProperty()
  @IsString()
  id: string;

  @ApiProperty()
  @IsString()
  section: string;

  @ApiProperty()
  @IsString()
  item: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  required?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  guidance?: string;
}

export class RequestTemplateDto {
  @ApiProperty()
  @IsString()
  title: string;

  @ApiProperty()
  @IsString()
  category: string;

  @ApiProperty()
  @IsString()
  description: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  controlRef?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  priority?: string;
}

export class TestProcedureTemplateDto {
  @ApiProperty()
  @IsString()
  title: string;

  @ApiProperty()
  @IsString()
  testType: string;

  @ApiProperty()
  @IsString()
  description: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  expectedResult?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  sampleSelection?: string;
}

export class CreateAuditTemplateDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty()
  @IsString()
  auditType: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  framework?: string;

  @ApiPropertyOptional({ type: [ChecklistItemDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChecklistItemDto)
  checklistItems?: ChecklistItemDto[];

  @ApiPropertyOptional({ type: [RequestTemplateDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RequestTemplateDto)
  requestTemplates?: RequestTemplateDto[];

  @ApiPropertyOptional({ type: [TestProcedureTemplateDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TestProcedureTemplateDto)
  testProcedureTemplates?: TestProcedureTemplateDto[];
}

export class UpdateAuditTemplateDto {
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
  @IsString()
  auditType?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  framework?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional({ type: [ChecklistItemDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChecklistItemDto)
  checklistItems?: ChecklistItemDto[];

  @ApiPropertyOptional({ type: [RequestTemplateDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RequestTemplateDto)
  requestTemplates?: RequestTemplateDto[];

  @ApiPropertyOptional({ type: [TestProcedureTemplateDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TestProcedureTemplateDto)
  testProcedureTemplates?: TestProcedureTemplateDto[];
}

export class CreateAuditFromTemplateDto {
  @ApiProperty()
  @IsString()
  templateId: string;

  @ApiProperty()
  @IsString()
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  plannedStartDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  plannedEndDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  createRequests?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  createTestProcedures?: boolean;
}

export class UpdateChecklistProgressDto {
  @ApiProperty()
  @IsString()
  itemId: string;

  @ApiProperty()
  @IsBoolean()
  completed: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;
}

