import { Global, Module } from '@nestjs/common';
import { JwtAuthGuard, RolesGuard, PermissionsGuard, PRISMA_SERVICE } from '@gigachad-grc/shared';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuthModule - Centralized authentication and authorization module
 *
 * This module provides JWT authentication plus role and permission guards.
 * as global providers so they can be used across all modules without
 * dependency resolution issues.
 *
 * @remarks
 * - JwtAuthGuard validates Keycloak-issued access tokens
 * - RolesGuard enforces role-based access control (uses optional Reflector)
 * - PermissionsGuard enforces permission-based access control (uses optional Reflector)
 * - Guards use optional Reflector injection with fallback to shared instance
 */
@Global()
@Module({
  providers: [
    // Re-provide PrismaService for guard dependencies
    PrismaService,
    // Keep Prisma available to modules that share this auth module.
    {
      provide: PRISMA_SERVICE,
      useExisting: PrismaService,
    },
    JwtAuthGuard,
    // RolesGuard and PermissionsGuard now use optional Reflector injection
    RolesGuard,
    PermissionsGuard,
  ],
  exports: [PrismaService, PRISMA_SERVICE, JwtAuthGuard, RolesGuard, PermissionsGuard],
})
export class AuthModule {}
