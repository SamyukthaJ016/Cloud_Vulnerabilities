interface ReportParams {
    framework: 'SOC2' | 'ISO27001' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'NIST-CSF';
    reportType: 'summary' | 'detailed' | 'executive' | 'gap-analysis';
    includeEvidence?: boolean;
    dateRange?: {
        start: string;
        end: string;
    };
}
interface ComplianceReport {
    reportId: string;
    reportType: string;
    framework: string;
    generatedAt: string;
    dateRange: {
        start: string;
        end: string;
    };
    summary: ReportSummary;
    sections: ReportSection[];
    recommendations: string[];
    nextSteps: string[];
}
interface ReportSummary {
    overallScore: number;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    totalControls: number;
    implementedControls: number;
    partiallyImplementedControls: number;
    notImplementedControls: number;
    criticalGaps: number;
    highGaps: number;
    mediumGaps: number;
    lowGaps: number;
}
interface ReportSection {
    title: string;
    description?: string;
    score?: number;
    status?: string;
    items: ReportItem[];
}
interface ReportItem {
    id: string;
    name: string;
    status: string;
    score?: number;
    description?: string;
    evidence?: string[];
    gaps?: string[];
    recommendations?: string[];
}
export declare function generateComplianceReport(params: ReportParams): Promise<ComplianceReport>;
export {};
//# sourceMappingURL=report-generator.d.ts.map