import { Module } from '@nestjs/common';
import { FindingsController } from './findings.controller';
import { FindingsService } from './findings.service';
import { NormalizerService } from './normalizer.service';
import { ArtifactsService } from './artifacts.service';

@Module({
  controllers: [FindingsController],
  providers: [FindingsService, NormalizerService, ArtifactsService],
  exports: [FindingsService],
})
export class FindingsModule {}
