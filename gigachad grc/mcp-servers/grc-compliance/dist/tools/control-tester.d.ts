interface ControlTestParams {
    controlId: string;
    controlType: 'technical' | 'administrative' | 'physical';
    testConfiguration?: {
        evidenceSource?: string;
        threshold?: number;
        criteria?: string[];
    };
}
interface BatchTestParams {
    controlIds: string[];
    parallel?: boolean;
    stopOnFailure?: boolean;
}
interface TestResult {
    controlId: string;
    testId: string;
    status: 'passed' | 'failed' | 'warning' | 'error' | 'not_applicable';
    score: number;
    maxScore: number;
    testedAt: string;
    duration: number;
    findings: TestFinding[];
    evidence: TestEvidence[];
    recommendations: string[];
}
interface TestFinding {
    type: 'pass' | 'fail' | 'warning' | 'info';
    criterion: string;
    actual: string;
    expected: string;
    details?: string;
}
interface TestEvidence {
    type: string;
    source: string;
    collectedAt: string;
    reference?: string;
}
interface BatchTestResult {
    batchId: string;
    startedAt: string;
    completedAt: string;
    totalTests: number;
    passed: number;
    failed: number;
    warnings: number;
    errors: number;
    results: TestResult[];
}
export declare function runControlTest(params: ControlTestParams): Promise<TestResult>;
export declare function runBatchControlTests(params: BatchTestParams): Promise<BatchTestResult>;
export {};
//# sourceMappingURL=control-tester.d.ts.map