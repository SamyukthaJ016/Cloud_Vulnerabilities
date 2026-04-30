import { Module } from '@nestjs/common';
import { OrganizationsController } from './organizations.controller';
import { OrganizationsService } from './organizations.service';
import { MembershipsService } from './memberships.service';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [UsersModule],
  controllers: [OrganizationsController],
  providers: [OrganizationsService, MembershipsService],
  exports: [OrganizationsService, MembershipsService],
})
export class OrganizationsModule {}
