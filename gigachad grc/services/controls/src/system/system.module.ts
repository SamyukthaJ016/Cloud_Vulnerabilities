import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SystemHealthService } from './system-health.service';
import { SystemHealthController } from './system-health.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [SystemHealthController],
  providers: [SystemHealthService],
  exports: [SystemHealthService],
})
export class SystemModule {}

