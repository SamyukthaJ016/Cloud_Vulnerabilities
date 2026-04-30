import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsInt, Min, Max, IsArray, IsEnum } from 'class-validator';
import { Type } from 'class-transformer';

export enum SearchEntityType {
  Control = 'control',
  Policy = 'policy',
  Risk = 'risk',
  Evidence = 'evidence',
  Task = 'task',
  Framework = 'framework',
}

export class GlobalSearchDto {
  @ApiProperty({ description: 'Search query string' })
  @IsString()
  query: string;

  @ApiPropertyOptional({ 
    description: 'Entity types to search',
    enum: SearchEntityType,
    isArray: true,
  })
  @IsOptional()
  @IsArray()
  @IsEnum(SearchEntityType, { each: true })
  entityTypes?: SearchEntityType[];

  @ApiPropertyOptional({ default: 1, minimum: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({ default: 20, minimum: 1, maximum: 100 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}

export class SearchResultItemDto {
  @ApiProperty()
  id: string;

  @ApiProperty({ enum: SearchEntityType })
  entityType: SearchEntityType;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiPropertyOptional()
  identifier?: string; // e.g., controlId, policyId

  @ApiPropertyOptional()
  category?: string;

  @ApiPropertyOptional({ type: [String] })
  tags?: string[];

  @ApiProperty()
  matchedField: string; // Which field matched

  @ApiProperty()
  url: string; // Frontend URL to navigate to
}

export class SearchResultDto {
  @ApiProperty()
  total: number;

  @ApiProperty()
  page: number;

  @ApiProperty()
  limit: number;

  @ApiProperty()
  query: string;

  @ApiProperty({ type: [SearchResultItemDto] })
  results: SearchResultItemDto[];

  @ApiProperty({ description: 'Search execution time in milliseconds' })
  took: number;
}
