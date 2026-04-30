import { Injectable, NotFoundException } from '@nestjs/common';
import { Scanner } from '@prisma/client';
import type { ScannerDto } from '@cloudguard/shared';
import { PrismaService } from '../../infra/prisma/prisma.service';

const INTERNAL_SCANNER_KEYS = new Set(['cloud']);

@Injectable()
export class ScannersService {
  constructor(private readonly prisma: PrismaService) {}

  async list(): Promise<ScannerDto[]> {
    const rows = await this.prisma.scanner.findMany({
      orderBy: { name: 'asc' },
    });
    return rows.filter((row) => !INTERNAL_SCANNER_KEYS.has(row.key)).map(toDto);
  }

  async getByKey(key: string): Promise<Scanner> {
    const scanner = await this.prisma.scanner.findUnique({ where: { key } });
    if (!scanner) throw new NotFoundException(`Scanner ${key} not found`);
    return scanner;
  }

  async getById(id: string): Promise<Scanner> {
    const scanner = await this.prisma.scanner.findUnique({ where: { id } });
    if (!scanner) throw new NotFoundException(`Scanner ${id} not found`);
    return scanner;
  }
}

export function toDto(s: Scanner): ScannerDto {
  return {
    id: s.id,
    key: s.key,
    name: s.name,
    description: s.description,
    version: s.version,
    category: s.category,
    iconUrl: s.iconUrl,
    dashboardBaseUrl: s.dashboardBaseUrl,
    credentialSchema: (s.credentialSchema ?? {}) as Record<string, unknown>,
    availability: s.availability,
    lastError: s.lastError,
  };
}
