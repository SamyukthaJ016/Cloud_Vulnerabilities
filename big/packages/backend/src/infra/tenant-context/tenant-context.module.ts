import { Global, Module } from '@nestjs/common';
import { TenantContextMiddleware } from './tenant-context.middleware';

@Global()
@Module({
  providers: [TenantContextMiddleware],
  exports: [TenantContextMiddleware],
})
export class TenantContextModule {}
