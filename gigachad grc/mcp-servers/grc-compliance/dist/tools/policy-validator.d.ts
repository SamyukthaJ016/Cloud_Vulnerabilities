interface PolicyValidationParams {
    policyId?: string;
    policyContent?: string;
    framework: 'SOC2' | 'ISO27001' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'NIST-CSF';
    requirements?: string[];
}
interface ValidationResult {
    policyId: string;
    framework: string;
    validatedAt: string;
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    findings: ValidationFinding[];
    missingElements: string[];
    recommendations: string[];
}
interface ValidationFinding {
    requirement: string;
    status: 'met' | 'partially_met' | 'not_met' | 'not_applicable';
    evidence?: string;
    gap?: string;
    recommendation?: string;
}
export declare function validatePolicyCompliance(params: PolicyValidationParams): Promise<ValidationResult>;
export {};
//# sourceMappingURL=policy-validator.d.ts.map