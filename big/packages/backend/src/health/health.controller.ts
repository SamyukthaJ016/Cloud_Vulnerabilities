import { Controller, Get } from '@nestjs/common';
import { HealthCheck, HealthCheckService } from '@nestjs/terminus';
import { Public } from '../common/decorators/public.decorator';

@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthCheckService) {}

  @Public()
  @Get()
  @HealthCheck()
  check() {
    // TODO: add Postgres / Redis / Vault / Razorpay indicators
    return this.health.check([]);
  }
}
