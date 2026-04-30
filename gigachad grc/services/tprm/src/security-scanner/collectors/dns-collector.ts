import { Injectable, Logger } from '@nestjs/common';
import * as dns from 'dns';
import { promisify } from 'util';
import { DNSSecurityInfo } from '../dto/security-scan.dto';

const resolveTxt = promisify(dns.resolveTxt);
const resolveCaa = promisify(dns.resolveCaa);

@Injectable()
export class DNSCollector {
  private readonly logger = new Logger(DNSCollector.name);

  /**
   * Collect DNS security information for a domain
   */
  async collect(targetUrl: string): Promise<DNSSecurityInfo> {
    const result: DNSSecurityInfo = {
      hasSPF: false,
      hasDMARC: false,
      hasDNSSEC: false,
      hasCAA: false,
    };

    try {
      const url = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
      const domain = url.hostname;

      // Check SPF record
      const spfResult = await this.checkSPF(domain);
      result.hasSPF = spfResult.hasSPF;
      result.spfRecord = spfResult.record;

      // Check DMARC record
      const dmarcResult = await this.checkDMARC(domain);
      result.hasDMARC = dmarcResult.hasDMARC;
      result.dmarcRecord = dmarcResult.record;

      // Check CAA record
      result.hasCAA = await this.checkCAA(domain);

      // DNSSEC is more complex to check - simplified check
      result.hasDNSSEC = await this.checkDNSSEC(domain);
    } catch (error) {
      this.logger.warn(`Failed to collect DNS info for ${targetUrl}: ${error.message}`);
    }

    return result;
  }

  private async checkSPF(domain: string): Promise<{ hasSPF: boolean; record?: string }> {
    try {
      const records = await resolveTxt(domain);
      for (const record of records) {
        const txt = record.join('');
        if (txt.toLowerCase().startsWith('v=spf1')) {
          return { hasSPF: true, record: txt };
        }
      }
    } catch (error) {
      this.logger.debug(`SPF lookup failed for ${domain}: ${error.message}`);
    }
    return { hasSPF: false };
  }

  private async checkDMARC(domain: string): Promise<{ hasDMARC: boolean; record?: string }> {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const records = await resolveTxt(dmarcDomain);
      for (const record of records) {
        const txt = record.join('');
        if (txt.toLowerCase().startsWith('v=dmarc1')) {
          return { hasDMARC: true, record: txt };
        }
      }
    } catch (error) {
      this.logger.debug(`DMARC lookup failed for ${domain}: ${error.message}`);
    }
    return { hasDMARC: false };
  }

  private async checkCAA(domain: string): Promise<boolean> {
    try {
      const records = await resolveCaa(domain);
      return records && records.length > 0;
    } catch (error) {
      this.logger.debug(`CAA lookup failed for ${domain}: ${error.message}`);
      return false;
    }
  }

  private async checkDNSSEC(domain: string): Promise<boolean> {
    // DNSSEC validation requires DNSKEY record type which is not supported
    // by Node.js built-in DNS resolver. A full implementation would need
    // an external library like dns-packet or dig command.
    // For now, we return false as we cannot verify DNSSEC status.
    this.logger.debug(`DNSSEC check skipped for ${domain} - requires external tools`);
    return false;
  }
}
