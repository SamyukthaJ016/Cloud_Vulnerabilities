interface OktaEvidenceParams {
    domain: string;
    checks?: string[];
}
interface EvidenceResult {
    service: string;
    collectedAt: string;
    domain: string;
    findings: unknown[];
    summary: {
        totalUsers: number;
        compliantUsers: number;
        nonCompliantUsers: number;
    };
}
export declare function collectOktaEvidence(params: OktaEvidenceParams): Promise<EvidenceResult>;
export {};
//# sourceMappingURL=okta-evidence.d.ts.map