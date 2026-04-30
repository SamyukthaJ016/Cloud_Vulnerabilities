import {
  BaseAIProvider,
  AIMessage,
  AICompletionOptions,
  AICompletionResult,
  AIProviderConfig,
} from './ai-provider.interface';

/**
 * Anthropic Provider Implementation
 * 
 * Supports Claude 3.5 Sonnet, Claude 3.5 Haiku, Claude 3 Opus, and Claude 3 Sonnet models.
 */
export class AnthropicProvider extends BaseAIProvider {
  readonly name = 'anthropic';

  private static readonly AVAILABLE_MODELS = [
    'claude-3-5-sonnet-20241022',
    'claude-3-5-haiku-20241022',
    'claude-3-opus-20240229',
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307',
  ];

  private static readonly API_VERSION = '2023-06-01';

  constructor(config?: Partial<AIProviderConfig>) {
    super({
      apiKey: config?.apiKey || process.env.ANTHROPIC_API_KEY || '',
      defaultModel: config?.defaultModel || process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022',
      defaultTemperature: config?.defaultTemperature ?? 0.7,
      defaultMaxTokens: config?.defaultMaxTokens ?? 4096,
      baseUrl: config?.baseUrl || 'https://api.anthropic.com/v1',
      timeout: config?.timeout ?? 60000,
    });
  }

  isConfigured(): boolean {
    return !!this.config.apiKey && this.config.apiKey.length > 0;
  }

  getAvailableModels(): string[] {
    return [...AnthropicProvider.AVAILABLE_MODELS];
  }

  isValidModel(model: string): boolean {
    return AnthropicProvider.AVAILABLE_MODELS.includes(model);
  }

  async complete(
    messages: AIMessage[],
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult> {
    if (!this.isConfigured()) {
      throw new Error('Anthropic API key is not configured. Please set ANTHROPIC_API_KEY environment variable.');
    }

    const effectiveOptions = this.getEffectiveOptions(options);

    // Anthropic uses a different message format - system is separate
    let systemPrompt: string | undefined;
    const anthropicMessages: AnthropicMessage[] = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemPrompt = msg.content;
      } else {
        anthropicMessages.push({
          role: msg.role as 'user' | 'assistant',
          content: msg.content,
        });
      }
    }

    // Anthropic requires messages to start with a user message
    if (anthropicMessages.length === 0 || anthropicMessages[0].role !== 'user') {
      throw new Error('Anthropic requires the first message to be from the user');
    }

    const requestBody: AnthropicRequest = {
      model: effectiveOptions.model,
      max_tokens: effectiveOptions.maxTokens || 4096,
      messages: anthropicMessages,
      temperature: effectiveOptions.temperature,
      top_p: effectiveOptions.topP,
    };

    if (systemPrompt) {
      requestBody.system = systemPrompt;
    }

    try {
      const response = await fetch(`${this.config.baseUrl}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.config.apiKey,
          'anthropic-version': AnthropicProvider.API_VERSION,
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(this.config.timeout || 60000),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`Anthropic API error: ${response.status} - ${errorBody}`);
      }

      const data = await response.json() as AnthropicResponse;

      // Extract text from content blocks
      const content = data.content
        .filter(block => block.type === 'text')
        .map(block => block.text)
        .join('');

      return {
        content,
        model: data.model,
        tokensUsed: {
          prompt: data.usage?.input_tokens || 0,
          completion: data.usage?.output_tokens || 0,
          total: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0),
        },
        finishReason: data.stop_reason || 'unknown',
      };
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error('Anthropic request timed out');
        }
        throw error;
      }
      throw new Error(`Anthropic request failed: ${String(error)}`);
    }
  }
}

// Anthropic API Types
interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface AnthropicRequest {
  model: string;
  max_tokens: number;
  messages: AnthropicMessage[];
  system?: string;
  temperature?: number;
  top_p?: number;
}

interface AnthropicResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{
    type: string;
    text: string;
  }>;
  model: string;
  stop_reason: string;
  stop_sequence: string | null;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

