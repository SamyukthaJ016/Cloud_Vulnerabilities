import { Global, Module } from '@nestjs/common';
import { JwtAuthGuard, RolesGuard, PermissionsGuard, PRISMA_SERVICE } from '@gigachad-grc/shared';
import { PrismaService } from '../prisma/prisma.service';

@Global()
@Module({
  providers: [
    PrismaService,
    {
      provide: PRISMA_SERVICE,
      useExisting: PrismaService,
    },
    JwtAuthGuard,
    RolesGuard,
    PermissionsGuard,
  ],
  exports: [PrismaService, PRISMA_SERVICE, JwtAuthGuard, RolesGuard, PermissionsGuard],
})
export class AuthModule {}
