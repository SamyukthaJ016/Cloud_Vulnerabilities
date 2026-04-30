import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';
class AIClient {
    openai = null;
    anthropic = null;
    config;
    constructor() {
        this.config = {
            provider: 'openai',
            model: 'gpt-5', // Latest GPT-5 model (Dec 2025)
            temperature: 0.3,
            maxTokens: 4096,
        };
        // Initialize clients based on available API keys
        if (process.env.OPENAI_API_KEY) {
            this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
            this.config.provider = 'openai';
            this.config.model = process.env.OPENAI_MODEL || 'gpt-5';
        }
        if (process.env.ANTHROPIC_API_KEY) {
            this.anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
            if (!this.openai) {
                this.config.provider = 'anthropic';
                this.config.model = process.env.ANTHROPIC_MODEL || 'claude-opus-4-5-20250514'; // Latest Claude Opus 4.5
            }
        }
    }
    isConfigured() {
        return this.openai !== null || this.anthropic !== null;
    }
    setConfig(config) {
        this.config = { ...this.config, ...config };
    }
    async complete(messages) {
        if (!this.isConfigured()) {
            throw new Error('AI client not configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable.');
        }
        if (this.config.provider === 'openai' && this.openai) {
            return this.completeWithOpenAI(messages);
        }
        else if (this.config.provider === 'anthropic' && this.anthropic) {
            return this.completeWithAnthropic(messages);
        }
        throw new Error('No AI provider available');
    }
    async completeWithOpenAI(messages) {
        if (!this.openai)
            throw new Error('OpenAI client not initialized');
        const response = await this.openai.chat.completions.create({
            model: this.config.model,
            messages: messages.map((m) => ({
                role: m.role,
                content: m.content,
            })),
            temperature: this.config.temperature,
            max_tokens: this.config.maxTokens,
        });
        return response.choices[0]?.message?.content || '';
    }
    async completeWithAnthropic(messages) {
        if (!this.anthropic)
            throw new Error('Anthropic client not initialized');
        // Extract system message
        const systemMessage = messages.find((m) => m.role === 'system');
        const otherMessages = messages.filter((m) => m.role !== 'system');
        // Use type assertion for SDK compatibility
        const client = this.anthropic;
        const response = await client.messages.create({
            model: this.config.model,
            max_tokens: this.config.maxTokens,
            system: systemMessage?.content,
            messages: otherMessages.map((m) => ({
                role: m.role,
                content: m.content,
            })),
        });
        const textContent = response.content.find((c) => c.type === 'text');
        return textContent?.text || '';
    }
    async completeJSON(messages) {
        const response = await this.complete(messages);
        // Try to extract JSON from the response
        try {
            // Look for JSON in code blocks
            const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[1].trim());
            }
            // Try to parse the entire response
            return JSON.parse(response);
        }
        catch {
            // If parsing fails, try to find JSON object in the response
            const objectMatch = response.match(/\{[\s\S]*\}/);
            if (objectMatch) {
                return JSON.parse(objectMatch[0]);
            }
            throw new Error('Failed to parse AI response as JSON');
        }
    }
}
// Export singleton instance
export const aiClient = new AIClient();
//# sourceMappingURL=ai-client.js.map