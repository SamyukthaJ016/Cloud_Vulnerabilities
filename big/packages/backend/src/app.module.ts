import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import { configuration } from './config/configuration';
import { validationSchema } from './config/validation.schema';

// Infra
import { PrismaModule } from './infra/prisma/prisma.module';
import { QueueModule } from './infra/queue/queue.module';
import { VaultModule } from './infra/vault/vault.module';
import { TenantContextModule } from './infra/tenant-context/tenant-context.module';
import { SessionModule } from './modules/session/session.module';

// Cross-cutting
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';

// Feature modules — one per flow-diagram domain
import { HealthModule } from './health/health.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { OrganizationsModule } from './modules/organizations/organizations.module';
import { RbacModule } from './modules/rbac/rbac.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { SecretsModule } from './modules/secrets/secrets.module';
import { PlansModule } from './modules/plans/plans.module';
import { SubscriptionsModule } from './modules/subscriptions/subscriptions.module';
import { BillingModule } from './modules/billing/billing.module';
import { BillingWebhooksModule } from './modules/billing-webhooks/billing-webhooks.module';
import { ScannersModule } from './modules/scanners/scanners.module';
import { ScansModule } from './modules/scans/scans.module';
import { ScannerCallbacksModule } from './modules/scanner-callbacks/scanner-callbacks.module';
import { ScannerClientsModule } from './modules/scanner-clients/scanner-clients.module';
import { FindingsModule } from './modules/findings/findings.module';
import { AuditModule } from './modules/audit/audit.module';
import { NotificationsModule } from './modules/notifications/notifications.module';
import { WebhooksOutboundModule } from './modules/webhooks-outbound/webhooks-outbound.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema,
    }),
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }]),

    // Infrastructure (global)
    PrismaModule,
    QueueModule,
    VaultModule,
    TenantContextModule,
    SessionModule,

    // Health
    HealthModule,

    // Identity & access
    AuthModule,
    UsersModule,
    OrganizationsModule,
    RbacModule,

    // Dashboard
    DashboardModule,

    // Secrets
    SecretsModule,

    // Billing
    PlansModule,
    SubscriptionsModule,
    BillingModule,
    BillingWebhooksModule,

    // Scanners
    ScannersModule,
    ScansModule,
    ScannerCallbacksModule,
    ScannerClientsModule,
    FindingsModule,

    // Observability
    AuditModule,
    NotificationsModule,
    WebhooksOutboundModule,
  ],
  providers: [
    // JwtAuthGuard runs first so req.user is populated before other guards/handlers.
    // Routes opt out via @Public() (login redirect, OAuth callback, webhooks, health).
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_FILTER, useClass: HttpExceptionFilter },
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
  ],
})
export class AppModule {}
