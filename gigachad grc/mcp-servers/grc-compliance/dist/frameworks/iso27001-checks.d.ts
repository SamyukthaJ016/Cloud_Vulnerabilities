interface ISO27001CheckParams {
    annexAControls?: string[];
    domains?: string[];
}
interface ISO27001CheckResult {
    framework: string;
    checkedAt: string;
    domains: DomainResult[];
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    findings: ISO27001Finding[];
    recommendations: string[];
}
interface DomainResult {
    domain: string;
    description: string;
    score: number;
    status: string;
    controls: ControlResult[];
}
interface ControlResult {
    id: string;
    name: string;
    status: 'implemented' | 'partially_implemented' | 'not_implemented' | 'not_applicable';
    score: number;
    findings: string[];
}
interface ISO27001Finding {
    control: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    finding: string;
    recommendation: string;
}
export declare function checkISO27001Controls(params: ISO27001CheckParams): Promise<ISO27001CheckResult>;
export {};
//# sourceMappingURL=iso27001-checks.d.ts.map