import { Controller, Post, Body, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { IsString, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { TrustAiService } from './trust-ai.service';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { JwtAuthGuard } from '../auth/dev-auth.guard';

// Maximum input lengths to prevent abuse
const MAX_QUESTION_LENGTH = 10000;
const MAX_ANSWER_LENGTH = 50000;

class DraftAnswerDto {
  @ApiProperty({ description: 'The question text to generate an answer for' })
  @IsString()
  @MinLength(1, { message: 'Question text cannot be empty' })
  @MaxLength(MAX_QUESTION_LENGTH, {
    message: `Question text cannot exceed ${MAX_QUESTION_LENGTH} characters`,
  })
  questionText: string;
}

class CategorizeQuestionDto {
  @ApiProperty({ description: 'The question text to categorize' })
  @IsString()
  @MinLength(1, { message: 'Question text cannot be empty' })
  @MaxLength(MAX_QUESTION_LENGTH, {
    message: `Question text cannot exceed ${MAX_QUESTION_LENGTH} characters`,
  })
  questionText: string;
}

class ImproveAnswerDto {
  @ApiProperty({ description: 'The original question text' })
  @IsString()
  @MinLength(1, { message: 'Question text cannot be empty' })
  @MaxLength(MAX_QUESTION_LENGTH, {
    message: `Question text cannot exceed ${MAX_QUESTION_LENGTH} characters`,
  })
  questionText: string;

  @ApiProperty({ description: 'The current answer to improve' })
  @IsString()
  @MinLength(1, { message: 'Current answer cannot be empty' })
  @MaxLength(MAX_ANSWER_LENGTH, {
    message: `Current answer cannot exceed ${MAX_ANSWER_LENGTH} characters`,
  })
  currentAnswer: string;
}

@Controller('trust-ai')
@UseGuards(JwtAuthGuard)
export class TrustAiController {
  constructor(private readonly aiService: TrustAiService) {}

  private getAuthorization(request: Request): string {
    const authorization = request.headers.authorization;
    if (typeof authorization !== 'string') {
      throw new UnauthorizedException('Authentication required');
    }
    return authorization;
  }

  @Post('draft-answer')
  draftAnswer(@Body() dto: DraftAnswerDto, @CurrentUser() user: UserContext, @Req() request: Request) {
    // SECURITY: Organization ID extracted from authenticated context, not query param
    return this.aiService.generateAnswerDraft(
      user.organizationId,
      dto.questionText,
      user.userId,
      this.getAuthorization(request),
    );
  }

  @Post('categorize')
  categorizeQuestion(@Body() dto: CategorizeQuestionDto, @CurrentUser() user: UserContext, @Req() request: Request) {
    // SECURITY: Organization ID extracted from authenticated context, not query param
    return this.aiService.categorizeQuestion(
      user.organizationId,
      dto.questionText,
      user.userId,
      this.getAuthorization(request),
    );
  }

  @Post('improve-answer')
  improveAnswer(@Body() dto: ImproveAnswerDto, @CurrentUser() user: UserContext, @Req() request: Request) {
    // SECURITY: Organization ID extracted from authenticated context, not query param
    return this.aiService.improveAnswer(
      user.organizationId,
      dto.questionText,
      dto.currentAnswer,
      user.userId,
      this.getAuthorization(request),
    );
  }
}
