interface HIPAACheckParams {
    ruleTypes?: ('privacy' | 'security' | 'breach_notification')[];
    safeguards?: ('administrative' | 'physical' | 'technical')[];
}
interface HIPAACheckResult {
    framework: string;
    checkedAt: string;
    rules: RuleResult[];
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    findings: HIPAAFinding[];
    recommendations: string[];
}
interface RuleResult {
    rule: string;
    description: string;
    score: number;
    status: string;
    requirements: RequirementResult[];
}
interface RequirementResult {
    id: string;
    name: string;
    status: 'implemented' | 'partially_implemented' | 'not_implemented' | 'not_applicable';
    score: number;
    findings: string[];
}
interface HIPAAFinding {
    requirement: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    finding: string;
    recommendation: string;
}
export declare function checkHIPAAControls(params: HIPAACheckParams): Promise<HIPAACheckResult>;
export {};
//# sourceMappingURL=hipaa-checks.d.ts.map