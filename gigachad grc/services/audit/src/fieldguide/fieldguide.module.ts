import { Module } from '@nestjs/common';
import { FieldGuideController } from './fieldguide.controller';
import { FieldGuideService } from './fieldguide.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [FieldGuideController],
  providers: [FieldGuideService],
  exports: [FieldGuideService],
})
export class FieldGuideModule {}

