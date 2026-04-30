import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { PrismaHealthIndicator } from './prisma.health';

@Module({
  controllers: [HealthController],
  providers: [PrismaHealthIndicator],
  exports: [PrismaHealthIndicator],
})
export class HealthModule {}
