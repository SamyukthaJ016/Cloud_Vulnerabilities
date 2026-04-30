import { IsString, IsOptional, IsArray, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// ===========================================
// Finding Categorization
// ===========================================

export class CategorizeFindingDto {
  @ApiProperty({ description: 'Finding title' })
  @IsString()
  title: string;

  @ApiProperty({ description: 'Finding description' })
  @IsString()
  description: string;

  @ApiPropertyOptional({ description: 'Additional context' })
  @IsOptional()
  @IsString()
  context?: string;

  @ApiPropertyOptional({ description: 'Framework for context' })
  @IsOptional()
  @IsString()
  framework?: string;
}

export class FindingCategorizationResult {
  @ApiProperty()
  severity: string;

  @ApiProperty()
  category: string;

  @ApiProperty()
  subcategory: string;

  @ApiProperty()
  controlDomain: string;

  @ApiProperty()
  relatedFrameworks: string[];

  @ApiProperty()
  suggestedTags: string[];

  @ApiProperty()
  confidence: number;

  @ApiProperty()
  reasoning: string;
}

// ===========================================
// Evidence Gap Analysis
// ===========================================

export class AnalyzeGapsDto {
  @ApiProperty({ description: 'Audit ID to analyze' })
  @IsUUID()
  auditId: string;

  @ApiPropertyOptional({ description: 'Specific control IDs to analyze' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  controlIds?: string[];
}

export class EvidenceGap {
  @ApiProperty()
  controlId: string;

  @ApiProperty()
  controlTitle: string;

  @ApiProperty()
  gapType: string; // missing, stale, incomplete

  @ApiProperty()
  description: string;

  @ApiProperty()
  priority: string;

  @ApiProperty()
  suggestedEvidence: string[];

  @ApiProperty()
  daysOverdue?: number;
}

export class GapAnalysisResult {
  @ApiProperty()
  auditId: string;

  @ApiProperty()
  totalControls: number;

  @ApiProperty()
  controlsWithEvidence: number;

  @ApiProperty()
  controlsWithGaps: number;

  @ApiProperty()
  overallCoverage: number;

  @ApiProperty({ type: [EvidenceGap] })
  gaps: EvidenceGap[];

  @ApiProperty()
  recommendations: string[];

  @ApiProperty()
  analyzedAt: Date;
}

// ===========================================
// Remediation Suggestions
// ===========================================

export class SuggestRemediationDto {
  @ApiProperty({ description: 'Finding ID' })
  @IsUUID()
  findingId: string;

  @ApiPropertyOptional({ description: 'Finding details if not fetching from DB' })
  @IsOptional()
  findingDetails?: {
    title: string;
    description: string;
    severity: string;
    category: string;
    controlId?: string;
  };
}

export class RemediationStep {
  @ApiProperty()
  stepNumber: number;

  @ApiProperty()
  title: string;

  @ApiProperty()
  description: string;

  @ApiProperty()
  estimatedDays: number;

  @ApiProperty()
  resources: string[];

  @ApiProperty()
  deliverables: string[];
}

export class RemediationSuggestion {
  @ApiProperty()
  findingId: string;

  @ApiProperty()
  summary: string;

  @ApiProperty()
  rootCauseAnalysis: string;

  @ApiProperty({ type: [RemediationStep] })
  steps: RemediationStep[];

  @ApiProperty()
  totalEstimatedDays: number;

  @ApiProperty()
  priority: string;

  @ApiProperty()
  riskIfNotRemediated: string;

  @ApiProperty()
  relatedControls: string[];

  @ApiProperty()
  industryBestPractices: string[];

  @ApiProperty()
  confidence: number;
}

// ===========================================
// Control Mapping
// ===========================================

export class MapControlsDto {
  @ApiProperty({ description: 'Audit request title' })
  @IsString()
  requestTitle: string;

  @ApiProperty({ description: 'Audit request description' })
  @IsString()
  requestDescription: string;

  @ApiPropertyOptional({ description: 'Framework to map to' })
  @IsOptional()
  @IsString()
  framework?: string;
}

export class ControlMapping {
  @ApiProperty()
  controlId: string;

  @ApiProperty()
  controlTitle: string;

  @ApiProperty()
  relevanceScore: number;

  @ApiProperty()
  mappingRationale: string;

  @ApiProperty()
  frameworkRequirements: string[];
}

export class ControlMappingResult {
  @ApiProperty({ type: [ControlMapping] })
  mappings: ControlMapping[];

  @ApiProperty()
  confidence: number;

  @ApiProperty()
  suggestedCategory: string;
}

// ===========================================
// Audit Summary Generation
// ===========================================

export class GenerateSummaryDto {
  @ApiProperty({ description: 'Audit ID' })
  @IsUUID()
  auditId: string;

  @ApiPropertyOptional({ description: 'Summary type' })
  @IsOptional()
  @IsString()
  summaryType?: 'executive' | 'technical' | 'management_letter';
}

export class AuditSummary {
  @ApiProperty()
  auditId: string;

  @ApiProperty()
  summaryType: string;

  @ApiProperty()
  executiveSummary: string;

  @ApiProperty()
  keyFindings: string[];

  @ApiProperty()
  riskOverview: string;

  @ApiProperty()
  recommendations: string[];

  @ApiProperty()
  conclusion: string;

  @ApiProperty()
  generatedAt: Date;
}

