import { Module } from '@nestjs/common';
import { TprmConfigController } from './tprm-config.controller';
import { TprmConfigService } from './tprm-config.service';
import { PrismaService } from '../common/prisma.service';

@Module({
  controllers: [TprmConfigController],
  providers: [TprmConfigService, PrismaService],
  exports: [TprmConfigService],
})
export class TprmConfigModule {}

