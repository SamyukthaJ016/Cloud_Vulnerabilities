import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { VendorsModule } from './vendors/vendors.module';
import { AssessmentsModule } from './assessments/assessments.module';
import { ContractsModule } from './contracts/contracts.module';
import { VendorAIModule } from './ai/vendor-ai.module';
import { TprmConfigModule } from './config/tprm-config.module';
import { RiskAssessmentModule } from './risk-assessment/risk-assessment.module';
import { SecurityScannerModule } from './security-scanner/security-scanner.module';
import { PrismaService } from './common/prisma.service';
import { AuditService } from './common/audit.service';
import { StorageModule, CacheModule, JwtAuthGuard, PRISMA_SERVICE } from '@gigachad-grc/shared';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minute
        limit: 100, // 100 requests per minute
      },
    ]),
    StorageModule.forRoot(),
    CacheModule.forRoot({ defaultTtl: 300 }), // 5-minute cache for dashboard widgets
    // RiskAssessmentModule and SecurityScannerModule must be imported BEFORE VendorsModule
    // because their routes (/vendors/:id/risk-assessment/*, /vendors/:id/security-scan/*)
    // are more specific than VendorsModule's catch-all /:id route
    RiskAssessmentModule,
    SecurityScannerModule,
    VendorsModule,
    AssessmentsModule,
    ContractsModule,
    VendorAIModule,
    TprmConfigModule,
  ],
  providers: [
    PrismaService,
    AuditService,
    // Keep Prisma available to modules that share this application module.
    {
      provide: PRISMA_SERVICE,
      useExisting: PrismaService,
    },
    JwtAuthGuard,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
  exports: [PrismaService, AuditService, JwtAuthGuard, PRISMA_SERVICE],
})
export class AppModule {}
