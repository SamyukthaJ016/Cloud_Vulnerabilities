import { Injectable, Logger, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import { Prisma, UserDelegation } from '@prisma/client';
import {
  CreateDelegationDto,
  UpdateDelegationDto,
  DelegationDto,
  DelegationListQueryDto,
  DelegationScope,
  DelegationStatus,
  ActiveDelegationsDto,
} from './dto/delegation.dto';
import {
  parsePaginationParams,
  createPaginatedResponse,
} from '@gigachad-grc/shared';

interface DelegationRecord {
  id: string;
  organizationId: string;
  delegatorId: string;
  delegateeId: string;
  startDate: Date;
  endDate: Date;
  scopes: DelegationScope[];
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
  revokedAt?: Date;
}


@Injectable()
export class DelegationService {
  private readonly logger = new Logger(DelegationService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createDelegation(
    organizationId: string,
    delegatorId: string,
    dto: CreateDelegationDto,
  ): Promise<DelegationDto> {
    // Validate dates
    const startDate = new Date(dto.startDate);
    const endDate = new Date(dto.endDate);
    const now = new Date();

    if (startDate >= endDate) {
      throw new BadRequestException('End date must be after start date');
    }

    if (endDate <= now) {
      throw new BadRequestException('End date must be in the future');
    }

    // Can't delegate to yourself
    if (delegatorId === dto.delegateeId) {
      throw new BadRequestException('Cannot delegate to yourself');
    }

    // Check if delegatee exists in same org
    const delegatee = await this.prisma.user.findFirst({
      where: { id: dto.delegateeId, organizationId },
    });

    if (!delegatee) {
      throw new NotFoundException('Delegatee not found in your organization');
    }

    const delegation = await this.withDelegatorLock(organizationId, delegatorId, async tx => {
      const existing = (await this.loadDelegations(organizationId, tx)).find(d =>
        d.organizationId === organizationId &&
        d.delegatorId === delegatorId &&
        d.delegateeId === dto.delegateeId &&
        !d.revokedAt &&
        d.startDate < endDate && d.endDate > startDate &&
        this.hasOverlappingScopes(d.scopes, dto.scopes || [DelegationScope.ALL])
      );

      if (existing) {
        throw new BadRequestException('Overlapping delegation already exists');
      }

      const id = crypto.randomUUID();
      const delegation: DelegationRecord = {
        id,
        organizationId,
        delegatorId,
        delegateeId: dto.delegateeId,
        startDate,
        endDate,
        scopes: dto.scopes || [DelegationScope.ALL],
        notes: dto.notes,
        createdAt: now,
        updatedAt: now,
      };

      await tx.userDelegation.create({ data: { id, ...this.delegationData(delegation) } });
      return delegation;
    });
    const id = delegation.id;
    this.logger.log(`Created delegation ${id} from ${delegatorId} to ${dto.delegateeId}`);

    return this.toDto(delegation);
  }

  async updateDelegation(
    organizationId: string,
    userId: string,
    delegationId: string,
    dto: UpdateDelegationDto,
  ): Promise<DelegationDto> {
    const updated = await this.withDelegatorLock(organizationId, userId, async tx => {
      const delegation = await this.loadDelegation(organizationId, delegationId, tx);
      if (!delegation || delegation.organizationId !== organizationId) {
        throw new NotFoundException(`Delegation ${delegationId} not found`);
      }

      // Only delegator can update
      if (delegation.delegatorId !== userId) {
        throw new ForbiddenException('Only the delegator can update this delegation');
      }

      if (delegation.revokedAt) {
        throw new BadRequestException('Cannot update revoked delegation');
      }

      const updated: DelegationRecord = {
        ...delegation,
        endDate: dto.endDate ? new Date(dto.endDate) : delegation.endDate,
        scopes: dto.scopes ?? delegation.scopes,
        notes: dto.notes ?? delegation.notes,
        updatedAt: new Date(),
      };

      if (updated.endDate <= updated.startDate || updated.endDate <= new Date()) {
        throw new BadRequestException('End date must be after start date and in the future');
      }
      const overlap = (await this.loadDelegations(organizationId, tx)).some(other =>
        other.id !== updated.id && other.delegatorId === userId &&
        other.delegateeId === updated.delegateeId && !other.revokedAt &&
        other.startDate < updated.endDate && other.endDate > updated.startDate &&
        this.hasOverlappingScopes(other.scopes, updated.scopes)
      );
      if (overlap) throw new BadRequestException('Overlapping delegation already exists');
      await tx.userDelegation.update({ where: { id: delegationId, organizationId }, data: this.delegationData(updated) });
      return updated;
    });
    return this.toDto(updated);
  }

  async revokeDelegation(
    organizationId: string,
    userId: string,
    delegationId: string,
  ): Promise<void> {
    await this.withDelegatorLock(organizationId, userId, async tx => {
      const delegation = await this.loadDelegation(organizationId, delegationId, tx);
      if (!delegation || delegation.organizationId !== organizationId) {
        throw new NotFoundException(`Delegation ${delegationId} not found`);
      }

      // Only delegator can revoke
      if (delegation.delegatorId !== userId) {
        throw new ForbiddenException('Only the delegator can revoke this delegation');
      }

      delegation.revokedAt = new Date();
      delegation.updatedAt = new Date();
      await tx.userDelegation.update({ where: { id: delegationId, organizationId }, data: this.delegationData(delegation) });

    });

    this.logger.log(`Revoked delegation ${delegationId}`);
  }

  async getDelegation(
    organizationId: string,
    delegationId: string,
  ): Promise<DelegationDto> {
    const delegation = await this.loadDelegation(organizationId, delegationId);
    if (!delegation || delegation.organizationId !== organizationId) {
      throw new NotFoundException(`Delegation ${delegationId} not found`);
    }
    return this.toDto(delegation);
  }

  async listDelegations(
    organizationId: string,
    userId: string,
    query: DelegationListQueryDto,
  ) {
    const pagination = parsePaginationParams({
      page: query.page,
      limit: query.limit,
    });

    let delegations = (await this.loadDelegations(organizationId))
      .filter(d => d.organizationId === organizationId);

    // Filter by role
    if (query.asDelegator && !query.asDelegatee) {
      delegations = delegations.filter(d => d.delegatorId === userId);
    } else if (query.asDelegatee && !query.asDelegator) {
      delegations = delegations.filter(d => d.delegateeId === userId);
    } else {
      // Show both by default
      delegations = delegations.filter(d =>
        d.delegatorId === userId || d.delegateeId === userId
      );
    }

    // Filter by status
    if (query.status) {
      delegations = delegations.filter(d => this.getStatus(d) === query.status);
    }

    delegations.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = delegations.length;
    const offset = (pagination.page - 1) * pagination.limit;
    const paginatedDelegations = delegations.slice(offset, offset + pagination.limit);

    return createPaginatedResponse(
      await Promise.all(paginatedDelegations.map(d => this.toDto(d))),
      total,
      pagination,
    );
  }

  async getActiveDelegations(
    organizationId: string,
    userId: string,
  ): Promise<ActiveDelegationsDto> {
    const now = new Date();

    const allDelegations = (await this.loadDelegations(organizationId))
      .filter(d =>
        d.organizationId === organizationId &&
        !d.revokedAt &&
        d.startDate <= now &&
        d.endDate > now
      );

    const outgoing = await Promise.all(
      allDelegations
        .filter(d => d.delegatorId === userId)
        .map(d => this.toDto(d))
    );

    const incoming = await Promise.all(
      allDelegations
        .filter(d => d.delegateeId === userId)
        .map(d => this.toDto(d))
    );

    return { outgoing, incoming };
  }

  async checkDelegation(
    organizationId: string,
    delegatorId: string,
    delegateeId: string,
    scope: DelegationScope,
  ): Promise<boolean> {
    const now = new Date();

    const delegation = (await this.loadDelegations(organizationId)).find(d =>
      d.organizationId === organizationId &&
      d.delegatorId === delegatorId &&
      d.delegateeId === delegateeId &&
      !d.revokedAt &&
      d.startDate <= now &&
      d.endDate > now &&
      (d.scopes.includes(DelegationScope.ALL) || d.scopes.includes(scope))
    );

    return !!delegation;
  }

  private withDelegatorLock<T>(organizationId: string, delegatorId: string, work: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(async tx => {
      // Serialize overlap checks and writes across service replicas. PostgreSQL
      // releases this transaction lock on commit, rollback, or connection loss.
      const key = JSON.stringify(['delegation', organizationId, delegatorId]);
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))`;
      return work(tx);
    });
  }

  private delegationData(delegation: DelegationRecord) {
    return {
      organizationId: delegation.organizationId, delegatorId: delegation.delegatorId,
      delegatorName: '', delegateId: delegation.delegateeId, delegateName: '',
      startDate: delegation.startDate, endDate: delegation.endDate,
      scope: delegation.scopes.length === 1 ? delegation.scopes[0] : 'specific', scopes: delegation.scopes,
      reason: delegation.notes, status: this.getStatus(delegation), revokedAt: delegation.revokedAt,
      updatedAt: delegation.updatedAt,
    };
  }

  private fromDelegation(row: UserDelegation): DelegationRecord {
    return {
      id: row.id, organizationId: row.organizationId, delegatorId: row.delegatorId, delegateeId: row.delegateId,
      startDate: row.startDate, endDate: row.endDate,
      scopes: (row.scopes.length ? row.scopes : [row.scope]) as DelegationScope[],
      notes: row.reason ?? undefined, revokedAt: row.revokedAt ?? undefined,
      createdAt: row.createdAt, updatedAt: row.updatedAt,
    };
  }

  private async loadDelegation(organizationId: string, id: string, db: Prisma.TransactionClient = this.prisma) {
    const row = await db.userDelegation.findFirst({ where: { id, organizationId } });
    return row ? this.fromDelegation(row) : undefined;
  }

  private async loadDelegations(organizationId: string, db: Prisma.TransactionClient = this.prisma) {
    return (await db.userDelegation.findMany({ where: { organizationId } })).map(row => this.fromDelegation(row));
  }

  private getStatus(delegation: DelegationRecord): DelegationStatus {
    const now = new Date();

    if (delegation.revokedAt) {
      return DelegationStatus.REVOKED;
    }

    if (delegation.endDate <= now) {
      return DelegationStatus.EXPIRED;
    }

    if (delegation.startDate > now) {
      return DelegationStatus.PENDING;
    }

    return DelegationStatus.ACTIVE;
  }

  private hasOverlappingScopes(scopes1: DelegationScope[], scopes2: DelegationScope[]): boolean {
    if (scopes1.includes(DelegationScope.ALL) || scopes2.includes(DelegationScope.ALL)) {
      return true;
    }
    return scopes1.some(s => scopes2.includes(s));
  }

  private async toDto(delegation: DelegationRecord): Promise<DelegationDto> {
    // Fetch user info
    const [delegator, delegatee] = await Promise.all([
      this.prisma.user.findUnique({
        where: { id: delegation.delegatorId },
        select: { displayName: true, email: true },
      }),
      this.prisma.user.findUnique({
        where: { id: delegation.delegateeId },
        select: { displayName: true, email: true },
      }),
    ]);

    return {
      id: delegation.id,
      delegatorId: delegation.delegatorId,
      delegatorName: delegator?.displayName || 'Unknown',
      delegatorEmail: delegator?.email || '',
      delegateeId: delegation.delegateeId,
      delegateeName: delegatee?.displayName || 'Unknown',
      delegateeEmail: delegatee?.email || '',
      startDate: delegation.startDate,
      endDate: delegation.endDate,
      scopes: delegation.scopes,
      status: this.getStatus(delegation),
      notes: delegation.notes,
      createdAt: delegation.createdAt,
      updatedAt: delegation.updatedAt,
    };
  }
}
