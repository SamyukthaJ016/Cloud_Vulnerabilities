interface PromptDefinition {
    description: string;
    arguments: {
        name: string;
        description: string;
        required: boolean;
    }[];
    template: string;
}
export declare const GRC_PROMPTS: Record<string, PromptDefinition>;
export declare function getPromptMessages(promptName: string, args: Record<string, string>): {
    role: 'user' | 'assistant';
    content: string;
}[];
export {};
//# sourceMappingURL=grc-prompts.d.ts.map