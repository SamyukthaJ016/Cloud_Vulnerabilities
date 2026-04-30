import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { ScannersService } from './scanners.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('scanners')
export class ScannersController {
  constructor(private readonly scanners: ScannersService) {}

  @Get()
  list() {
    return this.scanners.list();
  }
}
