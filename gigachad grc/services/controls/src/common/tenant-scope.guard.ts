import {
  Injectable,
  CanActivate,
  ExecutionContext,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Metadata key for tenant-scoped resources
 */
export const TENANT_SCOPED_KEY = 'tenantScoped';

/**
 * Decorator to mark a resource as tenant-scoped
 * This ensures the resource ID in the request belongs to the user's organization
 * 
 * Usage:
 * @TenantScoped('risk', 'id')  // Check that risk with :id belongs to user's org
 * @Get(':id')
 * async getRisk(@Param('id') id: string) { ... }
 */
export function TenantScoped(entityType: string, paramName: string = 'id') {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    Reflect.defineMetadata(
      TENANT_SCOPED_KEY,
      { entityType, paramName },
      target,
      propertyKey,
    );
    return descriptor;
  };
}

/**
 * Guard to verify tenant ownership of resources
 * 
 * This guard checks that any resource ID in the request (from params, query, or body)
 * belongs to the authenticated user's organization.
 * 
 * This prevents IDOR (Insecure Direct Object Reference) attacks where
 * a user might try to access another organization's data by guessing IDs.
 */
@Injectable()
export class TenantScopeGuard implements CanActivate {
  private readonly logger = new Logger(TenantScopeGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get the tenant scope metadata
    const scopeConfig = this.reflector.get<{ entityType: string; paramName: string }>(
      TENANT_SCOPED_KEY,
      context.getHandler(),
    );

    // If no scope config, allow the request
    if (!scopeConfig) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user?.organizationId) {
      throw new ForbiddenException('Authentication required');
    }

    const { entityType, paramName } = scopeConfig;
    
    // Get the resource ID from params, query, or body
    const resourceId = 
      request.params?.[paramName] || 
      request.query?.[paramName] || 
      request.body?.[paramName];

    if (!resourceId) {
      // No resource ID to check
      return true;
    }

    // Verify the resource belongs to the user's organization
    const isOwned = await this.verifyOwnership(
      entityType,
      resourceId,
      user.organizationId,
    );

    if (!isOwned) {
      this.logger.warn(
        `IDOR attempt blocked: user=${user.userId}, org=${user.organizationId}, ` +
        `entity=${entityType}, id=${resourceId}`
      );
      
      // Return 404 instead of 403 to avoid confirming resource existence
      throw new NotFoundException(`${entityType} not found`);
    }

    return true;
  }

  /**
   * Verify that a resource belongs to an organization
   */
  private async verifyOwnership(
    entityType: string,
    resourceId: string,
    organizationId: string,
  ): Promise<boolean> {
    try {
      // Map entity types to Prisma models
      const modelMap: Record<string, string> = {
        risk: 'risk',
        control: 'control',
        evidence: 'evidence',
        policy: 'policy',
        vendor: 'vendor',
        asset: 'asset',
        audit: 'audit',
        user: 'user',
        workspace: 'workspace',
        integration: 'integration',
        framework: 'framework',
        bcdrPlan: 'bCDRPlan',
        businessProcess: 'businessProcess',
        drTest: 'disasterRecoveryTest',
        runbook: 'runbook',
        trainingModule: 'trainingModule',
        phishingCampaign: 'phishingCampaign',
        notification: 'notification',
        comment: 'comment',
        task: 'task',
      };

      const modelName = modelMap[entityType];
      if (!modelName) {
        this.logger.warn(`Unknown entity type for tenant scoping: ${entityType}`);
        return true; // Allow if we don't know how to check
      }

      // Dynamic lookup using Prisma
      const model = (this.prisma as any)[modelName];
      if (!model) {
        this.logger.warn(`Prisma model not found: ${modelName}`);
        return true;
      }

      const record = await model.findFirst({
        where: {
          id: resourceId,
          organizationId,
        },
        select: { id: true },
      });

      return !!record;
    } catch (error) {
      this.logger.error(`Error checking ownership: ${error}`);
      return false;
    }
  }
}

/**
 * Helper function to add organization scoping to Prisma queries
 * Use this in services to ensure all queries are properly scoped
 * 
 * Usage:
 * const where = withTenantScope({ status: 'active' }, organizationId);
 * // Result: { status: 'active', organizationId: '...' }
 */
export function withTenantScope<T extends Record<string, any>>(
  where: T,
  organizationId: string,
): T & { organizationId: string } {
  return {
    ...where,
    organizationId,
  };
}

/**
 * Helper to verify an entity belongs to an organization before returning it
 * Throws NotFoundException if not found or not owned
 * 
 * Usage:
 * const risk = await this.prisma.risk.findFirst({ where: { id } });
 * return verifyTenantOwnership(risk, organizationId, 'Risk');
 */
export function verifyTenantOwnership<T extends { organizationId?: string | null }>(
  entity: T | null,
  organizationId: string,
  entityName: string = 'Resource',
): T {
  if (!entity) {
    throw new NotFoundException(`${entityName} not found`);
  }

  // Some entities (like global controls) may not have organizationId
  if (entity.organizationId && entity.organizationId !== organizationId) {
    throw new NotFoundException(`${entityName} not found`);
  }

  return entity;
}

/**
 * Prisma middleware to automatically add organization scoping
 * 
 * Note: This is a reference implementation. In practice, you may want
 * to be more selective about which models get automatic scoping.
 */
export function createTenantScopingMiddleware(getOrganizationId: () => string | null) {
  return async (params: any, next: any) => {
    const organizationId = getOrganizationId();
    
    if (!organizationId) {
      return next(params);
    }

    // Models that should be automatically scoped
    const scopedModels = [
      'Risk', 'Control', 'Evidence', 'Policy', 'Vendor', 'Asset',
      'Audit', 'Workspace', 'Integration', 'Notification', 'Task',
    ];

    if (!scopedModels.includes(params.model)) {
      return next(params);
    }

    // Add organizationId to queries
    if (['findFirst', 'findMany', 'findUnique', 'update', 'delete'].includes(params.action)) {
      if (params.args?.where) {
        params.args.where = {
          ...params.args.where,
          organizationId,
        };
      }
    }

    // Add organizationId to creates
    if (['create', 'createMany'].includes(params.action)) {
      if (params.args?.data) {
        if (Array.isArray(params.args.data)) {
          params.args.data = params.args.data.map((d: any) => ({
            ...d,
            organizationId,
          }));
        } else {
          params.args.data = {
            ...params.args.data,
            organizationId,
          };
        }
      }
    }

    return next(params);
  };
}

