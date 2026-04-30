import { Module } from '@nestjs/common';
import { ScannerClientsModule } from '../scanner-clients/scanner-clients.module';
import { ScannersController } from './scanners.controller';
import { ScannerAdminController } from './scanner-admin.controller';
import { ScannersService } from './scanners.service';
import { ScannerSyncService } from './scanner-sync.service';

@Module({
  imports: [ScannerClientsModule],
  controllers: [ScannersController, ScannerAdminController],
  providers: [ScannersService, ScannerSyncService],
  exports: [ScannersService],
})
export class ScannersModule {}
