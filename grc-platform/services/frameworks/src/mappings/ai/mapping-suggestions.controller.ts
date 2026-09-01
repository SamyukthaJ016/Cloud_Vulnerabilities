import { Body, Controller, HttpCode, HttpStatus, Post, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { Throttle } from '@nestjs/throttler';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentUser, JwtAuthGuard, Roles, RolesGuard, UserContext } from '@gigachad-grc/shared';
import { MappingSuggestionsService } from './mapping-suggestions.service';
import {
  SuggestMappingsRequestDto,
  SuggestMappingsResponseDto,
} from './dto/mapping-suggestion.dto';

@ApiTags('mappings')
@ApiBearerAuth()
@Controller('api/mappings')
@UseGuards(JwtAuthGuard, RolesGuard)
export class MappingSuggestionsController {
  constructor(private readonly service: MappingSuggestionsService) {}

  @Post('suggest')
  @HttpCode(HttpStatus.OK)
  @Roles('admin', 'compliance_manager')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({
    summary: 'AI mapping suggestions (requirement → controls or inverse)',
  })
  async suggest(
    @Body() dto: SuggestMappingsRequestDto,
    @CurrentUser() user: UserContext,
    @Req() request: Request,
  ): Promise<SuggestMappingsResponseDto> {
    const authorization = request.headers.authorization;
    if (typeof authorization !== 'string') {
      throw new UnauthorizedException('Authentication required');
    }
    return this.service.suggest(dto, user.userId, user.organizationId, authorization);
  }
}
