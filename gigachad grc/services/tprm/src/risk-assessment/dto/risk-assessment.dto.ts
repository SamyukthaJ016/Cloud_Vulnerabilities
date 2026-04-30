import { IsString, IsNumber, IsOptional, ValidateNested, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

// ============================================
// Risk Assessment Request DTOs
// ============================================

export class LikelihoodAssessmentDto {
  @IsNumber()
  @Min(5)
  @Max(25)
  frequency: number; // Threat event frequency score

  @IsNumber()
  @Min(5)
  @Max(25)
  capability: number; // Threat actor capability score

  @IsNumber()
  @Min(5)
  @Max(25)
  controlStrength: number; // Control strength score
}

export class ImpactAssessmentDto {
  @IsNumber()
  @Min(0)
  @Max(5)
  productivity: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  response: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  recovery: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  competitive: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  legal: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  reputation: number;
}

export class CreateRiskAssessmentDto {
  @IsString()
  title: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  assessor: string;

  @IsNumber()
  @Min(5)
  @Max(25)
  assetScore: number; // Asset criticality score (max of data type and infrastructure role)

  @IsNumber()
  @Min(5)
  @Max(25)
  threatScore: number; // Threat actor/event score (max of actor and objective)

  @ValidateNested()
  @Type(() => LikelihoodAssessmentDto)
  likelihood: LikelihoodAssessmentDto;

  @ValidateNested()
  @Type(() => ImpactAssessmentDto)
  impact: ImpactAssessmentDto;
}

// ============================================
// Risk Assessment Response Types
// ============================================

export interface LikelihoodResult {
  frequency: number;
  capability: number;
  controlStrength: number;
  total: number;
  level: 'Very Low' | 'Low' | 'Moderate' | 'High' | 'Very High';
  score: number; // Converted to 25-point scale
}

export interface ImpactResult {
  productivity: number;
  response: number;
  recovery: number;
  competitive: number;
  legal: number;
  reputation: number;
  total: number;
  level: 'Very Low' | 'Low' | 'Moderate' | 'High' | 'Very High';
  score: number; // Converted to 25-point scale
}

export interface RiskAssessmentResult {
  id: string;
  vendorId: string;
  title: string;
  description?: string;
  assessor: string;
  date: string;
  assetScore: number;
  threatScore: number;
  likelihood: LikelihoodResult;
  impact: ImpactResult;
  totalScore: number;
  riskLevel: 'Minimal' | 'Low' | 'Medium' | 'High' | 'Critical';
  recommendedAction: string;
  nextReviewDate: string;
}

// ============================================
// Assessment Option Constants
// ============================================

export const ASSET_DATA_TYPE_OPTIONS = [
  { value: 25, label: 'Sensitive end-user, customer, or employee data', description: 'PII, PHI, payment data' },
  { value: 20, label: 'Sensitive business information', description: 'Source code, contracts, financials' },
  { value: 10, label: 'Internal productivity data', description: 'Policies, documentation, internal tools' },
  { value: 5, label: 'Public data', description: 'Marketing materials, public documentation' },
];

export const ASSET_ROLE_OPTIONS = [
  { value: 25, label: 'Mission critical', description: 'Supports GA product uptime' },
  { value: 20, label: 'Business critical', description: 'Major disruption if unavailable' },
  { value: 10, label: 'Productivity enabling', description: 'Teams impacted if unavailable' },
  { value: 5, label: 'Limited impact', description: 'Alternatives available' },
  { value: 0, label: 'Negligible impact', description: 'Minimal business relevance' },
];

export const THREAT_ACTOR_OPTIONS = [
  { value: 25, label: 'Nation State', description: 'Geopolitical motivations' },
  { value: 20, label: 'Cybercriminal/Organized Crime', description: 'Profit motivated' },
  { value: 15, label: 'Hacktivist', description: 'Ideological motivations' },
  { value: 10, label: 'Malicious Insider', description: 'Discontent/financial gain' },
  { value: 5, label: 'Script Kiddie', description: 'Trivial motivations' },
];

export const THREAT_OBJECTIVE_OPTIONS = [
  { value: 25, label: 'Sabotage/Extortion', description: 'Ransomware, DDoS' },
  { value: 20, label: 'Data Theft', description: 'IP, customer data' },
  { value: 15, label: 'Fraud and Abuse', description: 'Account takeover' },
  { value: 10, label: 'Watering Hole', description: 'Using vendor to attack others' },
  { value: 5, label: 'Resource Hijacking', description: 'Cryptomining, etc.' },
];

export const LIKELIHOOD_FREQUENCY_OPTIONS = [
  { value: 25, label: '>100 times per year', description: 'Very frequent attacks' },
  { value: 20, label: '10-100 times per year', description: 'Frequent attacks' },
  { value: 15, label: '1-10 times per year', description: 'Occasional attacks' },
  { value: 10, label: '0.1-1 times per year', description: 'Rare attacks' },
  { value: 5, label: '<0.1 times per year', description: 'Very rare attacks' },
];

export const LIKELIHOOD_CAPABILITY_OPTIONS = [
  { value: 25, label: 'Default passwords/unpatched CVEs', description: 'Basic exploitation' },
  { value: 20, label: 'Basic scripting/known exploits', description: 'Script-level attacks' },
  { value: 15, label: 'Custom exploits/insider knowledge', description: 'Sophisticated attacks' },
  { value: 10, label: 'Zero-day exploits/nation-state tools', description: 'Advanced attacks' },
  { value: 5, label: 'Multiple zero-days/unprecedented', description: 'Extremely advanced' },
];

export const LIKELIHOOD_CONTROL_OPTIONS = [
  { value: 25, label: 'No controls/known vulnerabilities', description: 'Unprotected' },
  { value: 20, label: 'Basic controls only', description: 'Firewall, antivirus' },
  { value: 15, label: 'Standard controls', description: 'Patching, MFA, logging' },
  { value: 10, label: 'Advanced controls', description: 'SIEM, segmentation, threat detection' },
  { value: 5, label: 'Comprehensive controls', description: 'Zero-trust, threat hunting' },
];

export const IMPACT_PRODUCTIVITY_OPTIONS = [
  { value: 5, label: 'Unrecoverable failure / SEV 0', description: 'Complete service loss' },
  { value: 4, label: 'Critical teams unable to work', description: 'Major disruption' },
  { value: 3, label: 'SEV 1 incident', description: 'Significant impact' },
  { value: 2, label: 'Minor project delays', description: 'Limited impact' },
  { value: 1, label: 'SEV 2 incident', description: 'Minor impact' },
  { value: 0, label: 'No impact', description: 'No productivity loss' },
];

export const IMPACT_RESPONSE_OPTIONS = [
  { value: 5, label: 'Major negligent data breach', description: 'Exhausting all resources' },
  { value: 4, label: 'Public communications required', description: 'PR response needed' },
  { value: 3, label: 'Insurance claim / legal counsel', description: 'Legal involvement' },
  { value: 2, label: 'Confirmed security incident', description: 'Internal response' },
  { value: 1, label: 'System alerts only', description: 'Monitoring only' },
  { value: 0, label: 'No response needed', description: 'No action required' },
];

export const IMPACT_RECOVERY_OPTIONS = [
  { value: 5, label: 'Unrecoverable loss', description: 'Production data/services lost' },
  { value: 4, label: 'Major infrastructure rebuild', description: 'Cloud infrastructure' },
  { value: 3, label: 'Disaster recovery activation', description: 'DR site restoration' },
  { value: 2, label: 'Data restoration from backups', description: 'Backup recovery' },
  { value: 1, label: 'Quick rollback/minor fixes', description: 'Simple recovery' },
  { value: 0, label: 'No recovery needed', description: 'No data loss' },
];

export const IMPACT_COMPETITIVE_OPTIONS = [
  { value: 5, label: 'Product roadmaps/trade secrets exposed', description: 'IP theft' },
  { value: 4, label: 'R&D plans/M&A plans leaked', description: 'Strategic exposure' },
  { value: 2, label: 'Internal procedures exposed', description: 'Process exposure' },
  { value: 0, label: 'No competitive impact', description: 'No advantage lost' },
];

export const IMPACT_LEGAL_OPTIONS = [
  { value: 5, label: 'Criminal prosecution/regulatory shutdown', description: 'Severe legal' },
  { value: 4, label: 'Major regulatory fines', description: 'GDPR, HIPAA fines' },
  { value: 3, label: 'SLA/contract penalties', description: 'Key customer penalties' },
  { value: 1, label: 'Minor contract penalties', description: 'Small penalties' },
  { value: 0, label: 'No legal impact', description: 'No legal issues' },
];

export const IMPACT_REPUTATION_OPTIONS = [
  { value: 5, label: 'Loss of multiple key customers', description: 'Major customer churn' },
  { value: 4, label: 'Single key customer loss', description: 'Significant loss' },
  { value: 3, label: 'Decreased sales/market share', description: 'Business impact' },
  { value: 2, label: 'Negative media coverage', description: 'PR damage' },
  { value: 0, label: 'No reputation impact', description: 'No damage' },
];
