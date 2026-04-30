import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class PlansService {
  constructor(private readonly prisma: PrismaService) {}

  async listActive() {
    // TODO: return all plans with isActive=true + their entitlements
  }

  async getByKey(_key: string) {
    // TODO
  }
}
