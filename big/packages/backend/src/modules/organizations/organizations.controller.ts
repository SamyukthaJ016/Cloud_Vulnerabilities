import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { SessionService } from '../session/session.service';
import { OrganizationsService } from './organizations.service';
import { MembershipsService } from './memberships.service';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import { InviteMemberDto } from './dto/invite-member.dto';
import { ChangeMemberRoleDto } from './dto/change-member-role.dto';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('organizations')
export class OrganizationsController {
  constructor(
    private readonly orgsService: OrganizationsService,
    private readonly memberships: MembershipsService,
    private readonly session: SessionService,
  ) {}

  /** Returns the current org. Requires the user to already have one. */
  @Get('current')
  getCurrent(@OrgId() orgId: string) {
    if (!orgId) throw new BadRequestException('No organization assigned');
    return this.orgsService.getById(orgId);
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Get('current/members')
  listMembers(@OrgId() orgId: string) {
    return this.memberships.listMembers(orgId);
  }

  /**
   * Self-serve org creation (Pattern A — flow N1 escape).
   * The caller has just signed in but has no membership. We create the org +
   * admin membership transactionally, mint a fresh JWT with the new orgId, and
   * set the cookie so the frontend's next /auth/me sees the populated session.
   *
   * Note: this endpoint is intentionally NOT @Roles-gated because the caller
   * has no role yet. Just JwtAuthGuard.
   */
  @Post()
  async create(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateOrganizationDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.orgsService.createWithFirstAdmin({
      userId: user.userId,
      name: body.name,
      slug: body.slug,
      domain: body.domain,
    });

    // Refresh the session cookie so subsequent /auth/me reflects the new org+role.
    this.session.issue(res, {
      sub: user.userId,
      email: user.email,
      orgId: result.orgId,
      roleKey: result.roleKey,
    });

    return {
      organization: await this.orgsService.getById(result.orgId),
      roleKey: result.roleKey,
    };
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Post('current/members')
  invite(@OrgId() orgId: string, @Body() body: InviteMemberDto) {
    return this.orgsService.inviteMember({
      orgId,
      email: body.email,
      roleKey: body.roleKey,
    });
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Delete('current/members/:userId')
  removeMember(
    @OrgId() orgId: string,
    @CurrentUser() actor: AuthenticatedUser,
    @Param('userId') targetUserId: string,
  ) {
    return this.orgsService.removeMember({
      orgId,
      targetUserId,
      actorUserId: actor.userId,
    });
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Patch('current/members/:userId/role')
  changeRole(
    @OrgId() orgId: string,
    @CurrentUser() actor: AuthenticatedUser,
    @Param('userId') targetUserId: string,
    @Body() body: ChangeMemberRoleDto,
  ) {
    return this.orgsService.changeRole({
      orgId,
      targetUserId,
      actorUserId: actor.userId,
      newRoleKey: body.roleKey,
    });
  }
}
