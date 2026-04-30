/**
 * AI Provider Interface
 * 
 * Abstraction layer for different AI providers (OpenAI, Anthropic, etc.)
 * All providers must implement this interface for consistent behavior.
 */

export interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AICompletionOptions {
  model: string;
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
}

export interface AICompletionResult {
  content: string;
  model: string;
  tokensUsed: {
    prompt: number;
    completion: number;
    total: number;
  };
  finishReason: string;
}

export interface AIProviderConfig {
  apiKey: string;
  defaultModel: string;
  defaultTemperature?: number;
  defaultMaxTokens?: number;
  baseUrl?: string;
  timeout?: number;
}

export interface AIProvider {
  /**
   * Provider identifier
   */
  readonly name: string;

  /**
   * Check if the provider is properly configured and ready to use
   */
  isConfigured(): boolean;

  /**
   * Get available models for this provider
   */
  getAvailableModels(): string[];

  /**
   * Validate that a model is supported
   */
  isValidModel(model: string): boolean;

  /**
   * Generate a completion from messages
   */
  complete(
    messages: AIMessage[],
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult>;

  /**
   * Simple text completion (wraps complete() with single user message)
   */
  generateText(
    prompt: string,
    systemPrompt?: string,
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult>;

  /**
   * Generate structured JSON response
   */
  generateJSON<T>(
    prompt: string,
    systemPrompt: string,
    schema: string,
    options?: Partial<AICompletionOptions>
  ): Promise<T>;
}

/**
 * Base class with common functionality for AI providers
 */
export abstract class BaseAIProvider implements AIProvider {
  abstract readonly name: string;
  protected config: AIProviderConfig;

  constructor(config: AIProviderConfig) {
    this.config = config;
  }

  abstract isConfigured(): boolean;
  abstract getAvailableModels(): string[];
  abstract isValidModel(model: string): boolean;
  abstract complete(
    messages: AIMessage[],
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult>;

  async generateText(
    prompt: string,
    systemPrompt?: string,
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult> {
    const messages: AIMessage[] = [];
    
    if (systemPrompt) {
      messages.push({ role: 'system', content: systemPrompt });
    }
    
    messages.push({ role: 'user', content: prompt });
    
    return this.complete(messages, options);
  }

  async generateJSON<T>(
    prompt: string,
    systemPrompt: string,
    schema: string,
    options?: Partial<AICompletionOptions>
  ): Promise<T> {
    const enhancedSystemPrompt = `${systemPrompt}

IMPORTANT: You must respond with valid JSON only. No markdown, no code blocks, no explanation.
The response must conform to this schema:
${schema}`;

    const result = await this.generateText(prompt, enhancedSystemPrompt, options);
    
    // Clean the response - remove any markdown code blocks if present
    let cleanedContent = result.content.trim();
    if (cleanedContent.startsWith('```json')) {
      cleanedContent = cleanedContent.slice(7);
    } else if (cleanedContent.startsWith('```')) {
      cleanedContent = cleanedContent.slice(3);
    }
    if (cleanedContent.endsWith('```')) {
      cleanedContent = cleanedContent.slice(0, -3);
    }
    cleanedContent = cleanedContent.trim();
    
    try {
      return JSON.parse(cleanedContent) as T;
    } catch (error) {
      throw new Error(`Failed to parse AI response as JSON: ${error.message}. Response was: ${cleanedContent.substring(0, 200)}...`);
    }
  }

  protected getEffectiveOptions(options?: Partial<AICompletionOptions>): AICompletionOptions {
    return {
      model: options?.model || this.config.defaultModel,
      temperature: options?.temperature ?? this.config.defaultTemperature ?? 0.7,
      maxTokens: options?.maxTokens ?? this.config.defaultMaxTokens ?? 4096,
      topP: options?.topP ?? 1,
      frequencyPenalty: options?.frequencyPenalty ?? 0,
      presencePenalty: options?.presencePenalty ?? 0,
    };
  }
}

