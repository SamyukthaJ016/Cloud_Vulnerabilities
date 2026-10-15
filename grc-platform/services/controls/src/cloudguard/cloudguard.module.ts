import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CloudGuardController } from './cloudguard.controller';
import { CloudGuardService } from './cloudguard.service';
import { CloudGuardImportService } from './cloudguard-import.service';

@Module({
  imports: [ConfigModule],
  controllers: [CloudGuardController],
  providers: [CloudGuardService, CloudGuardImportService],
  exports: [CloudGuardService],
})
export class CloudGuardModule {}
