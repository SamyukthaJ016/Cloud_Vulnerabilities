import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SearchService } from './search.service';
import { GlobalSearchDto, SearchResultDto } from './dto/search.dto';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { DevAuthGuard } from '../auth/dev-auth.guard';

@ApiTags('Search')
@ApiBearerAuth()
@UseGuards(DevAuthGuard)
@Controller('api/search')
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  @Get()
  @ApiOperation({ summary: 'Global search across all entities' })
  @ApiResponse({ status: 200, type: SearchResultDto })
  async globalSearch(
    @CurrentUser() user: UserContext,
    @Query() dto: GlobalSearchDto,
  ): Promise<SearchResultDto> {
    return this.searchService.globalSearch(user.organizationId, dto);
  }
}
