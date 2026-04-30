import { Module } from '@nestjs/common';
import { WorkpapersController } from './workpapers.controller';
import { WorkpapersService } from './workpapers.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [WorkpapersController],
  providers: [WorkpapersService],
  exports: [WorkpapersService],
})
export class WorkpapersModule {}

