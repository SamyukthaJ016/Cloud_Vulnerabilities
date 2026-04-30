interface GDPRCheckParams {
    articles?: string[];
    dataProcessingActivities?: string[];
}
interface GDPRCheckResult {
    framework: string;
    checkedAt: string;
    chapters: ChapterResult[];
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    findings: GDPRFinding[];
    recommendations: string[];
}
interface ChapterResult {
    chapter: string;
    title: string;
    score: number;
    status: string;
    articles: ArticleResult[];
}
interface ArticleResult {
    id: string;
    name: string;
    status: 'implemented' | 'partially_implemented' | 'not_implemented' | 'not_applicable';
    score: number;
    findings: string[];
}
interface GDPRFinding {
    article: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    finding: string;
    recommendation: string;
    potentialFine?: string;
}
export declare function checkGDPRControls(params: GDPRCheckParams): Promise<GDPRCheckResult>;
export {};
//# sourceMappingURL=gdpr-checks.d.ts.map