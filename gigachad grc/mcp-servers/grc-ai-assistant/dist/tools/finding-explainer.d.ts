interface FindingExplainerParams {
    finding: {
        title: string;
        description: string;
        severity?: string;
        framework?: string;
        controlReference?: string;
    };
    audience?: 'technical' | 'executive' | 'auditor' | 'general';
    includeRemediation?: boolean;
}
interface FindingExplanation {
    findingTitle: string;
    explainedAt: string;
    audience: string;
    summary: string;
    plainLanguageExplanation: string;
    businessImpact: string;
    technicalDetails?: string;
    riskAssessment: {
        severity: string;
        likelihood: string;
        potentialImpact: string[];
    };
    remediation?: {
        overview: string;
        steps: RemediationStep[];
        estimatedEffort: string;
        priority: string;
    };
    relatedControls: string[];
    complianceImplications: string[];
}
interface RemediationStep {
    step: number;
    action: string;
    responsible: string;
    timeline: string;
    details?: string;
}
export declare function explainFinding(params: FindingExplainerParams): Promise<FindingExplanation>;
export {};
//# sourceMappingURL=finding-explainer.d.ts.map