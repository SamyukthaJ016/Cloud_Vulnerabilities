interface AWSEvidenceParams {
    services: string[];
    region?: string;
    includeConfigurations?: boolean;
}
interface EvidenceResult {
    service: string;
    collectedAt: string;
    region: string;
    findings: unknown[];
    summary: {
        totalResources: number;
        compliantResources: number;
        nonCompliantResources: number;
    };
}
export declare function collectAWSEvidence(params: AWSEvidenceParams): Promise<EvidenceResult[]>;
export {};
//# sourceMappingURL=aws-evidence.d.ts.map