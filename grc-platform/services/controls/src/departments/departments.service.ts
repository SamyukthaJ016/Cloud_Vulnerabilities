import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  CreateDepartmentDto,
  UpdateDepartmentDto,
  DepartmentDto,
  DepartmentTreeDto,
  AddDepartmentMemberDto,
  DepartmentMemberDto,
  CreateGroupHierarchyDto,
  GroupHierarchyDto,
  CreateGroupDepartmentScopeDto,
  GroupDepartmentScopeDto,
  EnhancedPermissionGroupDto,
} from './dto/department.dto';

@Injectable()
export class DepartmentsService {
  private readonly logger = new Logger(DepartmentsService.name);

  constructor(private readonly prisma: PrismaService) {}

  // ===========================================
  // Department CRUD
  // ===========================================

  async create(organizationId: string, dto: CreateDepartmentDto): Promise<DepartmentDto> {
    // Validate parent if provided
    if (dto.parentId) {
      const parent = await this.prisma.department.findFirst({
        where: { id: dto.parentId, organizationId },
      });
      if (!parent) {
        throw new NotFoundException('Parent department not found');
      }
    }

    // Check for duplicate code
    const existing = await this.prisma.department.findFirst({
      where: { organizationId, code: dto.code },
    });
    if (existing) {
      throw new ConflictException('Department code already exists');
    }

    const department = await this.prisma.department.create({
      data: {
        organizationId,
        name: dto.name,
        code: dto.code,
        description: dto.description,
        parentId: dto.parentId,
        headUserId: dto.headUserId,
        metadata: dto.metadata as any,
      },
      include: {
        parent: true,
        headUser: true,
        _count: { select: { members: true, children: true } },
      },
    });

    return this.toDepartmentDto(department);
  }

  async findAll(organizationId: string): Promise<DepartmentDto[]> {
    const departments = await this.prisma.department.findMany({
      where: { organizationId },
      include: {
        parent: true,
        headUser: true,
        _count: { select: { members: true, children: true } },
      },
      orderBy: { name: 'asc' },
    });

    return departments.map(d => this.toDepartmentDto(d));
  }

  async findOne(organizationId: string, id: string): Promise<DepartmentDto> {
    const department = await this.prisma.department.findFirst({
      where: { id, organizationId },
      include: {
        parent: true,
        headUser: true,
        _count: { select: { members: true, children: true } },
      },
    });

    if (!department) {
      throw new NotFoundException('Department not found');
    }

    return this.toDepartmentDto(department);
  }

  async update(
    organizationId: string,
    id: string,
    dto: UpdateDepartmentDto,
  ): Promise<DepartmentDto> {
    const existing = await this.prisma.department.findFirst({
      where: { id, organizationId },
    });

    if (!existing) {
      throw new NotFoundException('Department not found');
    }

    // Prevent circular hierarchy
    if (dto.parentId) {
      const wouldBeCircular = await this.checkCircularHierarchy(id, dto.parentId);
      if (wouldBeCircular) {
        throw new BadRequestException('Cannot create circular department hierarchy');
      }
    }

    const department = await this.prisma.department.update({
      where: { id },
      data: {
        name: dto.name,
        description: dto.description,
        parentId: dto.parentId,
        headUserId: dto.headUserId,
        isActive: dto.isActive,
        metadata: dto.metadata as any,
      },
      include: {
        parent: true,
        headUser: true,
        _count: { select: { members: true, children: true } },
      },
    });

    return this.toDepartmentDto(department);
  }

  async delete(organizationId: string, id: string): Promise<void> {
    const department = await this.prisma.department.findFirst({
      where: { id, organizationId },
      include: { _count: { select: { members: true, children: true } } },
    });

    if (!department) {
      throw new NotFoundException('Department not found');
    }

    if (department._count.children > 0) {
      throw new BadRequestException('Cannot delete department with child departments');
    }

    if (department._count.members > 0) {
      throw new BadRequestException('Cannot delete department with members. Remove members first.');
    }

    await this.prisma.department.delete({ where: { id } });
  }

  async getTree(organizationId: string): Promise<DepartmentTreeDto[]> {
    const departments = await this.prisma.department.findMany({
      where: { organizationId, isActive: true },
      include: {
        headUser: true,
        _count: { select: { members: true, children: true } },
      },
      orderBy: { name: 'asc' },
    });

    // Build tree structure
    const deptMap = new Map<string, DepartmentTreeDto>();
    const roots: DepartmentTreeDto[] = [];

    // First pass: create all nodes
    for (const dept of departments) {
      deptMap.set(dept.id, {
        ...this.toDepartmentDto(dept),
        children: [],
      });
    }

    // Second pass: build hierarchy
    for (const dept of departments) {
      const node = deptMap.get(dept.id)!;
      if (dept.parentId && deptMap.has(dept.parentId)) {
        deptMap.get(dept.parentId)!.children!.push(node);
      } else {
        roots.push(node);
      }
    }

    return roots;
  }

  // ===========================================
  // Department Membership
  // ===========================================

  async addMember(
    organizationId: string,
    departmentId: string,
    dto: AddDepartmentMemberDto,
  ): Promise<DepartmentMemberDto> {
    // Verify department exists
    const department = await this.prisma.department.findFirst({
      where: { id: departmentId, organizationId },
    });
    if (!department) {
      throw new NotFoundException('Department not found');
    }

    // Verify user exists
    const user = await this.prisma.user.findFirst({
      where: { id: dto.userId, organizationId },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // If setting as primary, unset other primary memberships
    if (dto.isPrimary) {
      await this.prisma.userDepartment.updateMany({
        where: { userId: dto.userId, isPrimary: true },
        data: { isPrimary: false },
      });
    }

    const membership = await this.prisma.userDepartment.upsert({
      where: {
        userId_departmentId: { userId: dto.userId, departmentId },
      },
      create: {
        userId: dto.userId,
        departmentId,
        isPrimary: dto.isPrimary ?? false,
        role: dto.role,
        startDate: new Date(),
      },
      update: {
        isPrimary: dto.isPrimary,
        role: dto.role,
      },
      include: { user: true, department: true },
    });

    return this.toMemberDto(membership);
  }

  async removeMember(
    organizationId: string,
    departmentId: string,
    userId: string,
  ): Promise<void> {
    const membership = await this.prisma.userDepartment.findFirst({
      where: {
        departmentId,
        userId,
        department: { organizationId },
      },
    });

    if (!membership) {
      throw new NotFoundException('Department membership not found');
    }

    await this.prisma.userDepartment.delete({ where: { id: membership.id } });
  }

  async getMembers(
    organizationId: string,
    departmentId: string,
  ): Promise<DepartmentMemberDto[]> {
    const members = await this.prisma.userDepartment.findMany({
      where: {
        departmentId,
        department: { organizationId },
      },
      include: { user: true, department: true },
      orderBy: { user: { displayName: 'asc' } },
    });

    return members.map(m => this.toMemberDto(m));
  }

  async getUserDepartments(
    organizationId: string,
    userId: string,
  ): Promise<DepartmentMemberDto[]> {
    const memberships = await this.prisma.userDepartment.findMany({
      where: {
        userId,
        department: { organizationId },
      },
      include: { user: true, department: true },
    });

    return memberships.map(m => this.toMemberDto(m));
  }

  // ===========================================
  // Permission Group Hierarchy
  // ===========================================

  async createGroupHierarchy(
    organizationId: string,
    dto: CreateGroupHierarchyDto,
  ): Promise<GroupHierarchyDto> {
    // Validate both groups exist
    const [parent, child] = await Promise.all([
      this.prisma.permissionGroup.findFirst({
        where: { id: dto.parentGroupId, organizationId },
      }),
      this.prisma.permissionGroup.findFirst({
        where: { id: dto.childGroupId, organizationId },
      }),
    ]);

    if (!parent) throw new NotFoundException('Parent group not found');
    if (!child) throw new NotFoundException('Child group not found');
    if (dto.parentGroupId === dto.childGroupId) {
      throw new BadRequestException('A group cannot be its own parent');
    }

    // Check for circular reference
    const wouldBeCircular = await this.checkGroupCircularHierarchy(
      dto.parentGroupId,
      dto.childGroupId,
    );
    if (wouldBeCircular) {
      throw new BadRequestException('Cannot create circular group hierarchy');
    }

    const hierarchy = await this.prisma.permissionGroupHierarchy.create({
      data: {
        parentGroupId: dto.parentGroupId,
        childGroupId: dto.childGroupId,
        inheritPermissions: dto.inheritPermissions ?? true,
      },
      include: { parentGroup: true, childGroup: true },
    });

    return this.toHierarchyDto(hierarchy);
  }

  async deleteGroupHierarchy(
    organizationId: string,
    parentGroupId: string,
    childGroupId: string,
  ): Promise<void> {
    const hierarchy = await this.prisma.permissionGroupHierarchy.findFirst({
      where: {
        parentGroupId,
        childGroupId,
        parentGroup: { organizationId },
      },
    });

    if (!hierarchy) {
      throw new NotFoundException('Group hierarchy not found');
    }

    await this.prisma.permissionGroupHierarchy.delete({ where: { id: hierarchy.id } });
  }

  async getGroupHierarchy(
    organizationId: string,
    groupId: string,
  ): Promise<{ parents: GroupHierarchyDto[]; children: GroupHierarchyDto[] }> {
    const [parents, children] = await Promise.all([
      this.prisma.permissionGroupHierarchy.findMany({
        where: { childGroupId: groupId, parentGroup: { organizationId } },
        include: { parentGroup: true, childGroup: true },
      }),
      this.prisma.permissionGroupHierarchy.findMany({
        where: { parentGroupId: groupId, childGroup: { organizationId } },
        include: { parentGroup: true, childGroup: true },
      }),
    ]);

    return {
      parents: parents.map(h => this.toHierarchyDto(h)),
      children: children.map(h => this.toHierarchyDto(h)),
    };
  }

  // ===========================================
  // Permission Group Department Scopes
  // ===========================================

  async createGroupDepartmentScope(
    organizationId: string,
    dto: CreateGroupDepartmentScopeDto,
  ): Promise<GroupDepartmentScopeDto> {
    // Validate group and department
    const [group, department] = await Promise.all([
      this.prisma.permissionGroup.findFirst({
        where: { id: dto.groupId, organizationId },
      }),
      this.prisma.department.findFirst({
        where: { id: dto.departmentId, organizationId },
      }),
    ]);

    if (!group) throw new NotFoundException('Permission group not found');
    if (!department) throw new NotFoundException('Department not found');

    const scope = await this.prisma.permissionGroupDepartmentScope.upsert({
      where: {
        groupId_departmentId: { groupId: dto.groupId, departmentId: dto.departmentId },
      },
      create: {
        groupId: dto.groupId,
        departmentId: dto.departmentId,
        scopeType: dto.scopeType,
        includeChildren: dto.includeChildren ?? true,
      },
      update: {
        scopeType: dto.scopeType,
        includeChildren: dto.includeChildren,
      },
      include: { group: true, department: true },
    });

    return this.toScopeDto(scope);
  }

  async deleteGroupDepartmentScope(
    organizationId: string,
    groupId: string,
    departmentId: string,
  ): Promise<void> {
    const scope = await this.prisma.permissionGroupDepartmentScope.findFirst({
      where: {
        groupId,
        departmentId,
        group: { organizationId },
      },
    });

    if (!scope) {
      throw new NotFoundException('Group department scope not found');
    }

    await this.prisma.permissionGroupDepartmentScope.delete({ where: { id: scope.id } });
  }

  async getGroupDepartmentScopes(
    organizationId: string,
    groupId: string,
  ): Promise<GroupDepartmentScopeDto[]> {
    const scopes = await this.prisma.permissionGroupDepartmentScope.findMany({
      where: { groupId, group: { organizationId } },
      include: { group: true, department: true },
    });

    return scopes.map(s => this.toScopeDto(s));
  }

  // ===========================================
  // Enhanced Permission Groups
  // ===========================================

  async getEnhancedPermissionGroup(
    organizationId: string,
    groupId: string,
  ): Promise<EnhancedPermissionGroupDto> {
    const group = await this.prisma.permissionGroup.findFirst({
      where: { id: groupId, organizationId },
      include: {
        parentGroups: { include: { parentGroup: true } },
        childGroups: { include: { childGroup: true } },
        departmentScopes: { include: { department: true } },
        _count: { select: { members: true } },
      },
    });

    if (!group) {
      throw new NotFoundException('Permission group not found');
    }

    // Calculate effective permissions (including inherited)
    const effectivePermissions = await this.calculateEffectivePermissions(groupId);

    return {
      id: group.id,
      organizationId: group.organizationId,
      name: group.name,
      description: group.description ?? undefined,
      permissions: group.permissions as any[],
      isSystem: group.isSystem,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
      parentGroups: group.parentGroups.map(h => this.toHierarchyDto(h)),
      childGroups: group.childGroups.map(h => this.toHierarchyDto(h)),
      departmentScopes: group.departmentScopes.map(s => ({
        id: s.id,
        groupId: s.groupId,
        departmentId: s.departmentId,
        scopeType: s.scopeType as any,
        includeChildren: s.includeChildren,
        createdAt: s.createdAt,
        departmentName: (s as any).department?.name,
      })),
      effectivePermissions,
      memberCount: group._count.members,
    };
  }

  // ===========================================
  // Private Helpers
  // ===========================================

  private async checkCircularHierarchy(
    departmentId: string,
    newParentId: string,
  ): Promise<boolean> {
    let currentId: string | null = newParentId;

    while (currentId) {
      if (currentId === departmentId) {
        return true;
      }
      const parent = await this.prisma.department.findUnique({
        where: { id: currentId },
        select: { parentId: true },
      });
      currentId = parent?.parentId ?? null;
    }

    return false;
  }

  private async checkGroupCircularHierarchy(
    parentGroupId: string,
    childGroupId: string,
  ): Promise<boolean> {
    // Check if parentGroupId is already a descendant of childGroupId
    const visited = new Set<string>();
    const queue = [childGroupId];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      const children = await this.prisma.permissionGroupHierarchy.findMany({
        where: { parentGroupId: currentId },
        select: { childGroupId: true },
      });

      for (const child of children) {
        if (child.childGroupId === parentGroupId) {
          return true;
        }
        queue.push(child.childGroupId);
      }
    }

    return false;
  }

  private async calculateEffectivePermissions(groupId: string): Promise<any[]> {
    const allPermissions: any[] = [];
    const visited = new Set<string>();
    const queue = [groupId];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      const group = await this.prisma.permissionGroup.findUnique({
        where: { id: currentId },
        select: { permissions: true },
      });

      if (group?.permissions) {
        allPermissions.push(...(group.permissions as any[]));
      }

      // Get parent groups that allow inheritance
      const parents = await this.prisma.permissionGroupHierarchy.findMany({
        where: { childGroupId: currentId, inheritPermissions: true },
        select: { parentGroupId: true },
      });

      for (const parent of parents) {
        queue.push(parent.parentGroupId);
      }
    }

    // Deduplicate permissions
    return Array.from(new Set(allPermissions.map(p => JSON.stringify(p)))).map(p =>
      JSON.parse(p),
    );
  }

  private toDepartmentDto(dept: any): DepartmentDto {
    return {
      id: dept.id,
      organizationId: dept.organizationId,
      name: dept.name,
      code: dept.code,
      description: dept.description,
      parentId: dept.parentId,
      headUserId: dept.headUserId,
      isActive: dept.isActive,
      metadata: dept.metadata,
      createdAt: dept.createdAt,
      updatedAt: dept.updatedAt,
      memberCount: dept._count?.members,
      childCount: dept._count?.children,
      parentName: dept.parent?.name,
      headUserName: dept.headUser?.displayName,
    };
  }

  private toMemberDto(membership: any): DepartmentMemberDto {
    return {
      id: membership.id,
      userId: membership.userId,
      departmentId: membership.departmentId,
      isPrimary: membership.isPrimary,
      role: membership.role,
      startDate: membership.startDate,
      endDate: membership.endDate,
      createdAt: membership.createdAt,
      userName: membership.user?.displayName,
      userEmail: membership.user?.email,
    };
  }

  private toHierarchyDto(hierarchy: any): GroupHierarchyDto {
    return {
      id: hierarchy.id,
      parentGroupId: hierarchy.parentGroupId,
      childGroupId: hierarchy.childGroupId,
      inheritPermissions: hierarchy.inheritPermissions,
      createdAt: hierarchy.createdAt,
      parentGroupName: hierarchy.parentGroup?.name,
      childGroupName: hierarchy.childGroup?.name,
    };
  }

  private toScopeDto(scope: any): GroupDepartmentScopeDto {
    return {
      id: scope.id,
      groupId: scope.groupId,
      departmentId: scope.departmentId,
      scopeType: scope.scopeType,
      includeChildren: scope.includeChildren,
      createdAt: scope.createdAt,
      groupName: scope.group?.name,
      departmentName: scope.department?.name,
    };
  }
}
