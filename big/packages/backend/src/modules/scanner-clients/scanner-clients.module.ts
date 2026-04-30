import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { DynamicScannerClient } from './dynamic-scanner.client';

@Module({
  imports: [HttpModule],
  providers: [DynamicScannerClient],
  exports: [DynamicScannerClient],
})
export class ScannerClientsModule {}
