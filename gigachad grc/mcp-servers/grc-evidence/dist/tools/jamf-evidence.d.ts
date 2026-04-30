interface JamfEvidenceParams {
    evidenceTypes?: string[];
    filters?: {
        deviceType?: 'computer' | 'mobile';
        managementStatus?: 'managed' | 'unmanaged';
    };
}
interface EvidenceResult {
    service: string;
    collectedAt: string;
    findings: unknown[];
    summary: {
        totalDevices: number;
        compliantDevices: number;
        nonCompliantDevices: number;
    };
}
export declare function collectJamfEvidence(params: JamfEvidenceParams): Promise<EvidenceResult>;
export {};
//# sourceMappingURL=jamf-evidence.d.ts.map