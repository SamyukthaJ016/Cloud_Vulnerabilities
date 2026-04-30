import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { DelegationService } from './delegation.service';
import {
  CreateDelegationDto,
  UpdateDelegationDto,
  DelegationDto,
  DelegationListQueryDto,
  ActiveDelegationsDto,
} from './dto/delegation.dto';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { DevAuthGuard } from '../auth/dev-auth.guard';

@ApiTags('Delegation')
@ApiBearerAuth()
@UseGuards(DevAuthGuard)
@Controller('api/delegations')
export class DelegationController {
  constructor(private readonly delegationService: DelegationService) {}

  @Get()
  @ApiOperation({ summary: 'List my delegations' })
  async listDelegations(
    @CurrentUser() user: UserContext,
    @Query() query: DelegationListQueryDto,
  ) {
    return this.delegationService.listDelegations(
      user.organizationId,
      user.userId,
      query,
    );
  }

  @Get('active')
  @ApiOperation({ summary: 'Get my active delegations (both incoming and outgoing)' })
  @ApiResponse({ status: 200, type: ActiveDelegationsDto })
  async getActiveDelegations(
    @CurrentUser() user: UserContext,
  ): Promise<ActiveDelegationsDto> {
    return this.delegationService.getActiveDelegations(
      user.organizationId,
      user.userId,
    );
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a delegation by ID' })
  @ApiResponse({ status: 200, type: DelegationDto })
  async getDelegation(
    @CurrentUser() user: UserContext,
    @Param('id') id: string,
  ): Promise<DelegationDto> {
    return this.delegationService.getDelegation(user.organizationId, id);
  }

  @Post()
  @ApiOperation({ summary: 'Create a new delegation' })
  @ApiResponse({ status: 201, type: DelegationDto })
  async createDelegation(
    @CurrentUser() user: UserContext,
    @Body() dto: CreateDelegationDto,
  ): Promise<DelegationDto> {
    return this.delegationService.createDelegation(
      user.organizationId,
      user.userId,
      dto,
    );
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update a delegation' })
  @ApiResponse({ status: 200, type: DelegationDto })
  async updateDelegation(
    @CurrentUser() user: UserContext,
    @Param('id') id: string,
    @Body() dto: UpdateDelegationDto,
  ): Promise<DelegationDto> {
    return this.delegationService.updateDelegation(
      user.organizationId,
      user.userId,
      id,
      dto,
    );
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoke a delegation' })
  async revokeDelegation(
    @CurrentUser() user: UserContext,
    @Param('id') id: string,
  ): Promise<void> {
    return this.delegationService.revokeDelegation(
      user.organizationId,
      user.userId,
      id,
    );
  }
}
