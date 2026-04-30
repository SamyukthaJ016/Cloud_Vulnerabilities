import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RbacService } from './rbac.service';

@UseGuards(JwtAuthGuard)
@Controller('rbac')
export class RbacController {
  constructor(private readonly rbacService: RbacService) {}

  @Get('roles')
  listRoles() {
    return this.rbacService.listRoles();
  }
}
