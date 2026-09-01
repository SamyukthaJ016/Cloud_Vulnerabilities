import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CloudGuardController } from './cloudguard.controller';
import { CloudGuardService } from './cloudguard.service';

@Module({
  imports: [ConfigModule],
  controllers: [CloudGuardController],
  providers: [CloudGuardService],
  exports: [CloudGuardService],
})
export class CloudGuardModule {}
