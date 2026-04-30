interface GitHubEvidenceParams {
    organization: string;
    repositories?: string[];
    checks?: string[];
}
interface EvidenceResult {
    service: string;
    collectedAt: string;
    organization: string;
    findings: unknown[];
    summary: {
        totalRepositories: number;
        compliantRepositories: number;
        nonCompliantRepositories: number;
    };
}
export declare function collectGitHubEvidence(params: GitHubEvidenceParams): Promise<EvidenceResult>;
export {};
//# sourceMappingURL=github-evidence.d.ts.map