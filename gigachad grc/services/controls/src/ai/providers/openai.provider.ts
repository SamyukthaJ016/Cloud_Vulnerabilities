import {
  BaseAIProvider,
  AIMessage,
  AICompletionOptions,
  AICompletionResult,
  AIProviderConfig,
} from './ai-provider.interface';

/**
 * OpenAI Provider Implementation
 * 
 * Supports GPT-4o, GPT-4o-mini, GPT-4-turbo, o1, and o1-mini models.
 */
export class OpenAIProvider extends BaseAIProvider {
  readonly name = 'openai';

  private static readonly AVAILABLE_MODELS = [
    'gpt-4o',
    'gpt-4o-mini',
    'gpt-4-turbo',
    'gpt-4-turbo-preview',
    'gpt-4',
    'gpt-3.5-turbo',
    'o1',
    'o1-mini',
    'o1-preview',
  ];

  constructor(config?: Partial<AIProviderConfig>) {
    super({
      apiKey: config?.apiKey || process.env.OPENAI_API_KEY || '',
      defaultModel: config?.defaultModel || process.env.OPENAI_MODEL || 'gpt-4o',
      defaultTemperature: config?.defaultTemperature ?? 0.7,
      defaultMaxTokens: config?.defaultMaxTokens ?? 4096,
      baseUrl: config?.baseUrl || 'https://api.openai.com/v1',
      timeout: config?.timeout ?? 60000,
    });
  }

  isConfigured(): boolean {
    return !!this.config.apiKey && this.config.apiKey.length > 0;
  }

  getAvailableModels(): string[] {
    return [...OpenAIProvider.AVAILABLE_MODELS];
  }

  isValidModel(model: string): boolean {
    return OpenAIProvider.AVAILABLE_MODELS.includes(model);
  }

  async complete(
    messages: AIMessage[],
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult> {
    if (!this.isConfigured()) {
      throw new Error('OpenAI API key is not configured. Please set OPENAI_API_KEY environment variable.');
    }

    const effectiveOptions = this.getEffectiveOptions(options);

    // o1 models don't support system messages or temperature
    const isO1Model = effectiveOptions.model.startsWith('o1');
    
    let formattedMessages = messages.map(m => ({
      role: m.role,
      content: m.content,
    }));

    // For o1 models, convert system messages to user messages
    if (isO1Model) {
      formattedMessages = formattedMessages.map(m => {
        if (m.role === 'system') {
          return { role: 'user' as const, content: `[System Instructions]\n${m.content}` };
        }
        return m;
      });
    }

    const requestBody: Record<string, unknown> = {
      model: effectiveOptions.model,
      messages: formattedMessages,
      max_tokens: effectiveOptions.maxTokens,
    };

    // o1 models don't support temperature
    if (!isO1Model) {
      requestBody.temperature = effectiveOptions.temperature;
      requestBody.top_p = effectiveOptions.topP;
      requestBody.frequency_penalty = effectiveOptions.frequencyPenalty;
      requestBody.presence_penalty = effectiveOptions.presencePenalty;
    }

    try {
      const response = await fetch(`${this.config.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(this.config.timeout || 60000),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`OpenAI API error: ${response.status} - ${errorBody}`);
      }

      const data = await response.json() as OpenAIResponse;

      return {
        content: data.choices[0]?.message?.content || '',
        model: data.model,
        tokensUsed: {
          prompt: data.usage?.prompt_tokens || 0,
          completion: data.usage?.completion_tokens || 0,
          total: data.usage?.total_tokens || 0,
        },
        finishReason: data.choices[0]?.finish_reason || 'unknown',
      };
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error('OpenAI request timed out');
        }
        throw error;
      }
      throw new Error(`OpenAI request failed: ${String(error)}`);
    }
  }
}

// OpenAI API Response Types
interface OpenAIResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

