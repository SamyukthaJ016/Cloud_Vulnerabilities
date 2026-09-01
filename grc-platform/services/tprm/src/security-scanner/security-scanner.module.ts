import { Module } from '@nestjs/common';
import { SecurityScannerController } from './security-scanner.controller';
import { SecurityScannerService } from './security-scanner.service';
import { SSLCollector } from './collectors/ssl-collector';
import { HeadersCollector } from './collectors/headers-collector';
import { DNSCollector } from './collectors/dns-collector';
import { WebCollector } from './collectors/web-collector';
import { ComplianceCollector } from './collectors/compliance-collector';
import { SubdomainCollector } from './collectors/subdomain-collector';
import { PageCrawler } from './collectors/page-crawler';
import { RiskAnalyzer } from './analyzers/risk-analyzer';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [SecurityScannerController],
  providers: [
    SecurityScannerService,
    SSLCollector,
    HeadersCollector,
    DNSCollector,
    WebCollector,
    ComplianceCollector,
    SubdomainCollector,
    PageCrawler,
    RiskAnalyzer,
    PrismaService,
    AuditService,
  ],
  exports: [SecurityScannerService, PageCrawler],
})
export class SecurityScannerModule {}
