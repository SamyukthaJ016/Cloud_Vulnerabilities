interface RemediationPrioritizerParams {
    findings: {
        id: string;
        title: string;
        severity: string;
        category?: string;
        estimatedEffort?: string;
    }[];
    constraints?: {
        budget?: number;
        timeframeWeeks?: number;
        teamSize?: number;
    };
    prioritizationStrategy?: 'risk_based' | 'compliance_deadline' | 'quick_wins' | 'balanced';
}
interface PrioritizedFinding {
    id: string;
    title: string;
    priority: number;
    priorityLabel: 'Critical' | 'High' | 'Medium' | 'Low';
    riskScore: number;
    effortScore: number;
    valueScore: number;
    recommendedPhase: number;
    estimatedWeeks: number;
    estimatedCost: number;
    rationale: string;
    dependencies: string[];
}
interface RemediationPlan {
    prioritizedAt: string;
    strategy: string;
    totalFindings: number;
    phases: RemediationPhase[];
    summary: {
        totalEstimatedCost: number;
        totalEstimatedWeeks: number;
        criticalFindings: number;
        highFindings: number;
        mediumFindings: number;
        lowFindings: number;
    };
    recommendations: string[];
    resourceRequirements: ResourceRequirement[];
}
interface RemediationPhase {
    phase: number;
    name: string;
    duration: string;
    findings: PrioritizedFinding[];
    milestones: string[];
}
interface ResourceRequirement {
    resource: string;
    quantity: number;
    notes: string;
}
export declare function prioritizeRemediation(params: RemediationPrioritizerParams): Promise<RemediationPlan>;
export {};
//# sourceMappingURL=remediation-prioritizer.d.ts.map