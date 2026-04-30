import {
  Controller,
  Post,
  Body,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { IsArray, IsString, IsIn, ArrayMaxSize, ArrayMinSize } from 'class-validator';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import { BulkOperationsService, BulkDeleteResult, BulkUpdateResult } from './bulk-operations.service';
import { UserContext } from '@gigachad-grc/shared';

class BulkDeleteDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(500)
  @IsString({ each: true })
  ids: string[];
}

class BulkUpdateStatusDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(500)
  @IsString({ each: true })
  ids: string[];

  @IsString()
  status: string;
}

class BulkAssignOwnerDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(500)
  @IsString({ each: true })
  ids: string[];

  @IsString()
  ownerId: string;

  @IsIn(['risk', 'control_implementation', 'evidence'])
  entityType: 'risk' | 'control_implementation' | 'evidence';
}

@ApiTags('bulk-operations')
@ApiBearerAuth()
@Controller('api/bulk')
@UseGuards(DevAuthGuard, PermissionGuard)
export class BulkOperationsController {
  constructor(private readonly bulkOps: BulkOperationsService) {}

  // ===========================
  // Risk Bulk Operations
  // ===========================

  @Post('risks/delete')
  @ApiOperation({ summary: 'Bulk delete risks (soft delete)' })
  @ApiResponse({ status: 200, description: 'Returns deletion result' })
  @RequirePermission(Resource.RISK, Action.DELETE)
  async bulkDeleteRisks(
    @User() user: UserContext,
    @Body() dto: BulkDeleteDto,
  ): Promise<BulkDeleteResult> {
    return this.bulkOps.bulkDeleteRisks(dto.ids, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }

  @Post('risks/status')
  @ApiOperation({ summary: 'Bulk update risk status' })
  @ApiResponse({ status: 200, description: 'Returns update result' })
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async bulkUpdateRiskStatus(
    @User() user: UserContext,
    @Body() dto: BulkUpdateStatusDto,
  ): Promise<BulkUpdateResult> {
    return this.bulkOps.bulkUpdateRiskStatus(dto.ids, dto.status, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }

  // ===========================
  // Control Bulk Operations
  // ===========================

  @Post('controls/delete')
  @ApiOperation({ summary: 'Bulk delete control implementations' })
  @ApiResponse({ status: 200, description: 'Returns deletion result' })
  @RequirePermission(Resource.CONTROLS, Action.DELETE)
  async bulkDeleteControls(
    @User() user: UserContext,
    @Body() dto: BulkDeleteDto,
  ): Promise<BulkDeleteResult> {
    return this.bulkOps.bulkDeleteControls(dto.ids, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }

  @Post('controls/status')
  @ApiOperation({ summary: 'Bulk update control implementation status' })
  @ApiResponse({ status: 200, description: 'Returns update result' })
  @RequirePermission(Resource.CONTROLS, Action.UPDATE)
  async bulkUpdateControlStatus(
    @User() user: UserContext,
    @Body() dto: BulkUpdateStatusDto,
  ): Promise<BulkUpdateResult> {
    return this.bulkOps.bulkUpdateControlStatus(dto.ids, dto.status, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }

  // ===========================
  // Evidence Bulk Operations
  // ===========================

  @Post('evidence/delete')
  @ApiOperation({ summary: 'Bulk delete evidence (soft delete)' })
  @ApiResponse({ status: 200, description: 'Returns deletion result' })
  @RequirePermission(Resource.EVIDENCE, Action.DELETE)
  async bulkDeleteEvidence(
    @User() user: UserContext,
    @Body() dto: BulkDeleteDto,
  ): Promise<BulkDeleteResult> {
    return this.bulkOps.bulkDeleteEvidence(dto.ids, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }

  // ===========================
  // Cross-Entity Operations
  // ===========================

  @Post('assign-owner')
  @ApiOperation({ summary: 'Bulk assign owner to entities' })
  @ApiResponse({ status: 200, description: 'Returns assignment result' })
  @RequirePermission(Resource.SETTINGS, Action.UPDATE)
  async bulkAssignOwner(
    @User() user: UserContext,
    @Body() dto: BulkAssignOwnerDto,
  ): Promise<BulkUpdateResult> {
    return this.bulkOps.bulkAssignOwner(dto.entityType, dto.ids, dto.ownerId, {
      organizationId: user.organizationId,
      userId: user.userId,
      userEmail: user.email,
      userName: user.name,
    });
  }
}

