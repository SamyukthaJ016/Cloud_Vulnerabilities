type AIProvider = 'openai' | 'anthropic';
interface AIConfig {
    provider: AIProvider;
    model: string;
    temperature: number;
    maxTokens: number;
}
interface AIMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
}
declare class AIClient {
    private openai;
    private anthropic;
    private config;
    constructor();
    isConfigured(): boolean;
    setConfig(config: Partial<AIConfig>): void;
    complete(messages: AIMessage[]): Promise<string>;
    private completeWithOpenAI;
    private completeWithAnthropic;
    completeJSON<T>(messages: AIMessage[]): Promise<T>;
}
export declare const aiClient: AIClient;
export {};
//# sourceMappingURL=ai-client.d.ts.map