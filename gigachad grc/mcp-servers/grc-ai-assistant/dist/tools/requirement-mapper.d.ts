interface RequirementMapperParams {
    control: {
        id?: string;
        title: string;
        description: string;
        category?: string;
    };
    targetFrameworks: string[];
    confidenceThreshold?: number;
}
interface RequirementMapping {
    framework: string;
    requirement: string;
    requirementTitle: string;
    confidence: number;
    rationale: string;
    coverage: 'full' | 'partial' | 'minimal';
}
interface RequirementMapperResult {
    controlId: string;
    controlTitle: string;
    mappedAt: string;
    mappings: RequirementMapping[];
    unmappedFrameworks: string[];
    suggestedEnhancements: string[];
}
export declare function mapRequirements(params: RequirementMapperParams): Promise<RequirementMapperResult>;
export {};
//# sourceMappingURL=requirement-mapper.d.ts.map