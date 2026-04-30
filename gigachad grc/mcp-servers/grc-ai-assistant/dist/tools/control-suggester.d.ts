interface ControlSuggestionParams {
    risk: {
        title: string;
        description: string;
        category?: string;
        currentLikelihood?: string;
        currentImpact?: string;
    };
    frameworks?: string[];
    maxSuggestions?: number;
}
interface ControlSuggestion {
    controlId: string;
    title: string;
    description: string;
    type: 'preventive' | 'detective' | 'corrective' | 'compensating';
    category: string;
    implementation: {
        steps: string[];
        estimatedEffort: string;
        estimatedCost: string;
        prerequisites: string[];
    };
    effectiveness: {
        likelihoodReduction: number;
        impactReduction: number;
        overallEffectiveness: string;
    };
    frameworkMappings: {
        framework: string;
        requirement: string;
    }[];
    priority: 'critical' | 'high' | 'medium' | 'low';
    rationale: string;
}
interface ControlSuggestionResult {
    riskTitle: string;
    analyzedAt: string;
    suggestions: ControlSuggestion[];
    quickWins: string[];
    longTermStrategies: string[];
}
export declare function suggestControls(params: ControlSuggestionParams): Promise<ControlSuggestionResult>;
export {};
//# sourceMappingURL=control-suggester.d.ts.map