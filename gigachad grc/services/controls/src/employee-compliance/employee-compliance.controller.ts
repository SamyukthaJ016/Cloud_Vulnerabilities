import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { EmployeeComplianceService } from './employee-compliance.service';
import { ComplianceScoreService } from './compliance-score.service';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import type { UserContext } from '@gigachad-grc/shared';

@ApiTags('Employee Compliance')
@Controller('api/employee-compliance')
@UseGuards(DevAuthGuard)
export class EmployeeComplianceController {
  constructor(
    private readonly employeeComplianceService: EmployeeComplianceService,
    private readonly complianceScoreService: ComplianceScoreService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'List employees with compliance data' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiQuery({ name: 'department', required: false, type: String })
  @ApiQuery({ name: 'status', required: false, type: String })
  @ApiQuery({ name: 'complianceStatus', required: false, type: String })
  @ApiQuery({ name: 'sortBy', required: false, type: String })
  @ApiQuery({ name: 'sortOrder', required: false, type: String })
  async listEmployees(
    @User() user: UserContext,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('search') search?: string,
    @Query('department') department?: string,
    @Query('status') status?: string,
    @Query('complianceStatus') complianceStatus?: 'compliant' | 'at_risk' | 'non_compliant',
    @Query('sortBy') sortBy?: string,
    @Query('sortOrder') sortOrder?: 'asc' | 'desc',
  ) {
    return this.employeeComplianceService.listEmployees({
      organizationId: user.organizationId,
      page: page ? parseInt(page, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
      search,
      department,
      status,
      complianceStatus,
      sortBy,
      sortOrder,
    });
  }

  @Get('dashboard')
  @ApiOperation({ summary: 'Get compliance dashboard metrics' })
  async getDashboard(@User() user: UserContext) {
    return this.employeeComplianceService.getDashboardMetrics(user.organizationId);
  }

  @Get('departments')
  @ApiOperation({ summary: 'Get unique departments' })
  async getDepartments(@User() user: UserContext) {
    return this.employeeComplianceService.getDepartments(user.organizationId);
  }

  @Get('missing')
  @ApiOperation({ summary: 'Find employees missing data from certain systems' })
  async getMissingData(@User() user: UserContext) {
    return this.employeeComplianceService.findMissingData(user.organizationId);
  }

  @Post('sync')
  @ApiOperation({ summary: 'Trigger sync from all employee-related integrations' })
  async triggerSync(@User() user: UserContext) {
    return this.employeeComplianceService.triggerSync(user.organizationId);
  }

  @Post('recalculate-scores')
  @ApiOperation({ summary: 'Recalculate compliance scores for all employees' })
  async recalculateScores(@User() user: UserContext) {
    const count = await this.complianceScoreService.recalculateOrganizationScores(
      user.organizationId,
    );
    return { message: `Recalculated scores for ${count} employees` };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get detailed employee compliance profile' })
  async getEmployeeDetail(
    @User() user: UserContext,
    @Param('id') id: string,
  ) {
    return this.employeeComplianceService.getEmployeeDetail(
      user.organizationId,
      id,
    );
  }

  @Get(':id/score')
  @ApiOperation({ summary: 'Get employee compliance score breakdown' })
  async getEmployeeScore(@Param('id') id: string) {
    return this.complianceScoreService.calculateEmployeeScore(id);
  }

  @Post(':id/recalculate')
  @ApiOperation({ summary: 'Recalculate compliance score for a single employee' })
  async recalculateEmployeeScore(@Param('id') id: string) {
    await this.complianceScoreService.updateEmployeeScore(id);
    return { message: 'Score recalculated' };
  }
}

