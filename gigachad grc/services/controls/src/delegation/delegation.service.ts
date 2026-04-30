import { Injectable, Logger, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
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

// In-memory store
const delegationStore = new Map<string, DelegationRecord>();

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

    // Check for overlapping delegations
    const existing = Array.from(delegationStore.values()).find(d => 
      d.organizationId === organizationId &&
      d.delegatorId === delegatorId &&
      d.delegateeId === dto.delegateeId &&
      !d.revokedAt &&
      d.endDate > now &&
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

    delegationStore.set(id, delegation);
    this.logger.log(`Created delegation ${id} from ${delegatorId} to ${dto.delegateeId}`);

    return this.toDto(delegation);
  }

  async updateDelegation(
    organizationId: string,
    userId: string,
    delegationId: string,
    dto: UpdateDelegationDto,
  ): Promise<DelegationDto> {
    const delegation = delegationStore.get(delegationId);
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

    delegationStore.set(delegationId, updated);
    return this.toDto(updated);
  }

  async revokeDelegation(
    organizationId: string,
    userId: string,
    delegationId: string,
  ): Promise<void> {
    const delegation = delegationStore.get(delegationId);
    if (!delegation || delegation.organizationId !== organizationId) {
      throw new NotFoundException(`Delegation ${delegationId} not found`);
    }

    // Only delegator can revoke
    if (delegation.delegatorId !== userId) {
      throw new ForbiddenException('Only the delegator can revoke this delegation');
    }

    delegation.revokedAt = new Date();
    delegation.updatedAt = new Date();
    delegationStore.set(delegationId, delegation);

    this.logger.log(`Revoked delegation ${delegationId}`);
  }

  async getDelegation(
    organizationId: string,
    delegationId: string,
  ): Promise<DelegationDto> {
    const delegation = delegationStore.get(delegationId);
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

    let delegations = Array.from(delegationStore.values())
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

    const allDelegations = Array.from(delegationStore.values())
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

    const delegation = Array.from(delegationStore.values()).find(d =>
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
