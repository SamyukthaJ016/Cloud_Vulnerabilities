interface SOC2CheckParams {
    trustServiceCategories?: ('security' | 'availability' | 'processing_integrity' | 'confidentiality' | 'privacy')[];
    controlPoints?: string[];
}
interface SOC2CheckResult {
    framework: string;
    checkedAt: string;
    categories: CategoryResult[];
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    findings: SOC2Finding[];
    recommendations: string[];
}
interface CategoryResult {
    category: string;
    description: string;
    score: number;
    status: string;
    controlPoints: ControlPointResult[];
}
interface ControlPointResult {
    id: string;
    name: string;
    status: 'implemented' | 'partially_implemented' | 'not_implemented' | 'not_applicable';
    score: number;
    findings: string[];
}
interface SOC2Finding {
    controlPoint: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    finding: string;
    recommendation: string;
}
export declare function checkSOC2Controls(params: SOC2CheckParams): Promise<SOC2CheckResult>;
export {};
//# sourceMappingURL=soc2-checks.d.ts.map