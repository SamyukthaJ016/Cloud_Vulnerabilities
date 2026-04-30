interface ScreenshotParams {
    url: string;
    selector?: string;
    waitForSelector?: string;
    fullPage?: boolean;
    authentication?: {
        type: 'basic' | 'bearer' | 'cookie';
        credentials: Record<string, string>;
    };
}
interface ScreenshotResult {
    type: string;
    url: string;
    collectedAt: string;
    screenshot: string;
    metadata: {
        width: number;
        height: number;
        format: string;
        size: number;
        captureTime: number;
    };
    pageInfo: {
        title: string;
        statusCode: number;
        loadTime: number;
    };
}
export declare function captureScreenshot(params: ScreenshotParams): Promise<ScreenshotResult>;
export {};
//# sourceMappingURL=screenshot-capture.d.ts.map