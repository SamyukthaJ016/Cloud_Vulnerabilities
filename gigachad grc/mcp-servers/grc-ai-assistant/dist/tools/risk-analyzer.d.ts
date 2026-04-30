interface RiskAnalysisParams {
    riskDescription: string;
    context?: {
        industry?: string;
        organizationSize?: string;
        frameworks?: string[];
        existingControls?: string[];
    };
    includeQuantitative?: boolean;
}
interface RiskAnalysisResult {
    riskId: string;
    analyzedAt: string;
    qualitativeAnalysis: {
        inherentRisk: {
            likelihood: string;
            likelihoodScore: number;
            impact: string;
            impactScore: number;
            riskLevel: string;
            riskScore: number;
        };
        residualRisk: {
            likelihood: string;
            likelihoodScore: number;
            impact: string;
            impactScore: number;
            riskLevel: string;
            riskScore: number;
        };
        riskCategory: string;
        riskOwnerSuggestion: string;
    };
    quantitativeAnalysis?: {
        annualizedLossExpectancy: number;
        singleLossExpectancy: number;
        annualRateOfOccurrence: number;
        assetValue: number;
        exposureFactor: number;
        costOfControls: number;
        riskReductionBenefit: number;
    };
    mitigationStrategies: MitigationStrategy[];
    relatedRisks: string[];
    complianceImpact: ComplianceImpact[];
    rationale: string;
}
interface MitigationStrategy {
    strategy: string;
    type: 'avoid' | 'mitigate' | 'transfer' | 'accept';
    effectiveness: string;
    estimatedCost: string;
    implementation: string[];
    timeline: string;
}
interface ComplianceImpact {
    framework: string;
    affectedControls: string[];
    impact: string;
}
export declare function analyzeRisk(params: RiskAnalysisParams): Promise<RiskAnalysisResult>;
export {};
//# sourceMappingURL=risk-analyzer.d.ts.map