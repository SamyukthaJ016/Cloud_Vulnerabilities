type PolicyType = 'information_security' | 'access_control' | 'data_classification' | 'incident_response' | 'acceptable_use' | 'password' | 'remote_work' | 'vendor_management' | 'data_retention' | 'privacy';
interface PolicyDraftParams {
    policyType: PolicyType;
    frameworks?: string[];
    organizationContext?: {
        name?: string;
        industry?: string;
        size?: string;
        specificRequirements?: string[];
    };
    format?: 'markdown' | 'html' | 'plain';
}
interface PolicyDraftResult {
    policyType: string;
    generatedAt: string;
    format: string;
    content: string;
    sections: PolicySection[];
    metadata: {
        version: string;
        effectiveDate: string;
        reviewDate: string;
        owner: string;
        approver: string;
    };
    frameworkAlignment: {
        framework: string;
        requirements: string[];
    }[];
}
interface PolicySection {
    title: string;
    content: string;
    subsections?: PolicySection[];
}
export declare function draftPolicy(params: PolicyDraftParams): Promise<PolicyDraftResult>;
export {};
//# sourceMappingURL=policy-drafter.d.ts.map