interface GapAnalyzerParams {
    currentControls: {
        id: string;
        title: string;
        status: string;
    }[];
    targetFramework: string;
    includeRoadmap?: boolean;
}
interface GapAnalysisResult {
    analyzedAt: string;
    targetFramework: string;
    currentState: {
        totalControls: number;
        implementedControls: number;
        partialControls: number;
        notImplementedControls: number;
        coveragePercentage: number;
    };
    gaps: ComplianceGap[];
    coveredRequirements: CoveredRequirement[];
    roadmap?: ImplementationRoadmap;
    prioritizedActions: string[];
    estimatedEffort: {
        totalWeeks: number;
        totalCost: string;
        resourcesNeeded: string[];
    };
}
interface ComplianceGap {
    requirement: string;
    requirementTitle: string;
    gapType: 'missing' | 'partial' | 'documentation';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    currentState: string;
    requiredState: string;
    remediationSteps: string[];
}
interface CoveredRequirement {
    requirement: string;
    requirementTitle: string;
    coveringControls: string[];
    coverageLevel: 'full' | 'partial';
}
interface ImplementationRoadmap {
    phases: RoadmapPhase[];
    milestones: Milestone[];
    dependencies: Dependency[];
}
interface RoadmapPhase {
    phase: number;
    name: string;
    duration: string;
    objectives: string[];
    deliverables: string[];
    requirements: string[];
}
interface Milestone {
    name: string;
    targetDate: string;
    criteria: string[];
}
interface Dependency {
    from: string;
    to: string;
    type: string;
}
export declare function analyzeComplianceGap(params: GapAnalyzerParams): Promise<GapAnalysisResult>;
export {};
//# sourceMappingURL=gap-analyzer.d.ts.map