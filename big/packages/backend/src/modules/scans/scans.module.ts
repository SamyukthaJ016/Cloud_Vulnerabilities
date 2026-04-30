import { Module } from '@nestjs/common';
import { ScannersModule } from '../scanners/scanners.module';
import { ScannerClientsModule } from '../scanner-clients/scanner-clients.module';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  imports: [ScannersModule, ScannerClientsModule],
  controllers: [ScansController],
  providers: [ScansService],
  exports: [ScansService],
})
export class ScansModule {}
