import { Module } from '@nestjs/common';
import { FrameworkCatalogController } from './catalog.controller';
import { FrameworkCatalogService } from './catalog.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [FrameworkCatalogController],
  providers: [FrameworkCatalogService],
  exports: [FrameworkCatalogService],
})
export class FrameworkCatalogModule {}
