import { Global, Module } from '@nestjs/common';
import { RbacController } from './rbac.controller';
import { RbacService } from './rbac.service';
import { EntitlementsService } from './entitlements.service';

@Global()
@Module({
  controllers: [RbacController],
  providers: [RbacService, EntitlementsService],
  exports: [RbacService, EntitlementsService],
})
export class RbacModule {}
