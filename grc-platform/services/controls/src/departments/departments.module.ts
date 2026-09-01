import { Module } from '@nestjs/common';
import { DepartmentsService } from './departments.service';
import { DepartmentsController, PermissionGroupsEnhancedController } from './departments.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [DepartmentsService],
  controllers: [DepartmentsController, PermissionGroupsEnhancedController],
  exports: [DepartmentsService],
})
export class DepartmentsModule {}
