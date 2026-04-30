import { Test, TestingModule } from '@nestjs/testing';
import { Logger, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { WorkflowsService } from './workflows.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  CreateWorkflowDto,
  UpdateWorkflowDto,
  CreateApprovalRequestDto,
  ApprovalActionDto,
  WorkflowEntityType,
  WorkflowTrigger,
  ApprovalType,
  ApprovalRequestStatus,
} from './dto/workflow.dto';

// Create mock functions
const mockUserFindUnique = jest.fn();
const mockMembershipFindMany = jest.fn();

const mockPrisma = {
  user: {
    findUnique: mockUserFindUnique,
  },
  userGroupMembership: {
    findMany: mockMembershipFindMany,
  },
};

describe('WorkflowsService', () => {
  let service: WorkflowsService;

  const mockOrganizationId = 'org-123';
  const mockUserId = 'user-123';

  beforeEach(async () => {
    // Reset all mocks
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WorkflowsService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    })
      .setLogger(new Logger('WorkflowsServiceTest'))
      .compile();

    service = module.get<WorkflowsService>(WorkflowsService);
  });

  // ==================== Workflow Tests ====================

  describe('createWorkflow', () => {
    const createDto: CreateWorkflowDto = {
      name: 'Policy Approval',
      description: 'Multi-step policy approval workflow',
      entityType: WorkflowEntityType.Policy,
      trigger: WorkflowTrigger.Manual,
      approvalType: ApprovalType.Sequential,
      steps: [
        {
          name: 'Manager Review',
          order: 1,
          approverRoles: ['compliance_manager'],
          timeoutHours: 48,
        },
        {
          name: 'Executive Approval',
          order: 2,
          approverRoles: ['admin'],
          timeoutHours: 72,
        },
      ],
    };

    it('should create a workflow with sequential steps', async () => {
      const result = await service.createWorkflow(mockOrganizationId, mockUserId, createDto);

      expect(result.id).toBeDefined();
      expect(result.name).toBe('Policy Approval');
      expect(result.entityType).toBe(WorkflowEntityType.Policy);
      expect(result.steps).toHaveLength(2);
      expect(result.steps[0].order).toBe(1);
      expect(result.steps[1].order).toBe(2);
      expect(result.isActive).toBe(true);
    });

    it('should sort steps by order', async () => {
      const dtoWithUnorderedSteps: CreateWorkflowDto = {
        ...createDto,
        steps: [
          { name: 'Step 3', order: 3, approverRoles: ['admin'] },
          { name: 'Step 1', order: 1, approverRoles: ['admin'] },
          { name: 'Step 2', order: 2, approverRoles: ['admin'] },
        ],
      };

      const result = await service.createWorkflow(mockOrganizationId, mockUserId, dtoWithUnorderedSteps);

      expect(result.steps[0].name).toBe('Step 1');
      expect(result.steps[1].name).toBe('Step 2');
      expect(result.steps[2].name).toBe('Step 3');
    });

    it('should default to Manual trigger when not specified', async () => {
      const dtoWithoutTrigger: CreateWorkflowDto = {
        name: 'Test Workflow',
        entityType: WorkflowEntityType.Control,
        steps: [{ name: 'Step 1', order: 1, approverRoles: ['admin'] }],
      };

      const result = await service.createWorkflow(mockOrganizationId, mockUserId, dtoWithoutTrigger);

      expect(result.trigger).toBe(WorkflowTrigger.Manual);
    });

    it('should default to Sequential approval type when not specified', async () => {
      const dtoWithoutType: CreateWorkflowDto = {
        name: 'Test Workflow',
        entityType: WorkflowEntityType.Control,
        steps: [{ name: 'Step 1', order: 1, approverRoles: ['admin'] }],
      };

      const result = await service.createWorkflow(mockOrganizationId, mockUserId, dtoWithoutType);

      expect(result.approvalType).toBe(ApprovalType.Sequential);
    });
  });

  describe('getWorkflow', () => {
    it('should return a workflow by ID', async () => {
      // First create a workflow
      const created = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Test Workflow',
        entityType: WorkflowEntityType.Risk,
        steps: [{ name: 'Step 1', order: 1, approverRoles: ['admin'] }],
      });

      const result = await service.getWorkflow(mockOrganizationId, created.id);

      expect(result.id).toBe(created.id);
      expect(result.name).toBe('Test Workflow');
    });

    it('should throw NotFoundException for non-existent workflow', async () => {
      await expect(
        service.getWorkflow(mockOrganizationId, 'nonexistent'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException for workflow from different organization', async () => {
      const created = await service.createWorkflow('other-org', mockUserId, {
        name: 'Other Org Workflow',
        entityType: WorkflowEntityType.Risk,
        steps: [{ name: 'Step 1', order: 1, approverRoles: ['admin'] }],
      });

      await expect(
        service.getWorkflow(mockOrganizationId, created.id),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateWorkflow', () => {
    it('should update workflow properties', async () => {
      const created = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Original Name',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step 1', order: 1, approverRoles: ['admin'] }],
      });

      const updateDto: UpdateWorkflowDto = {
        name: 'Updated Name',
        description: 'Updated description',
      };

      const result = await service.updateWorkflow(mockOrganizationId, created.id, updateDto);

      expect(result.name).toBe('Updated Name');
      expect(result.description).toBe('Updated description');
    });

    it('should update steps when provided', async () => {
      const created = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Old Step', order: 1, approverRoles: ['admin'] }],
      });

      const result = await service.updateWorkflow(mockOrganizationId, created.id, {
        steps: [
          { name: 'New Step 1', order: 1, approverRoles: ['manager'] },
          { name: 'New Step 2', order: 2, approverRoles: ['admin'] },
        ],
      });

      expect(result.steps).toHaveLength(2);
      expect(result.steps[0].name).toBe('New Step 1');
    });

    it('should toggle isActive', async () => {
      const created = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverRoles: ['admin'] }],
        isActive: true,
      });

      const result = await service.updateWorkflow(mockOrganizationId, created.id, {
        isActive: false,
      });

      expect(result.isActive).toBe(false);
    });
  });

  describe('deleteWorkflow', () => {
    it('should delete a workflow without pending requests', async () => {
      const created = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'To Delete',
        entityType: WorkflowEntityType.Control,
        steps: [{ name: 'Step', order: 1, approverRoles: ['admin'] }],
      });

      await service.deleteWorkflow(mockOrganizationId, created.id);

      await expect(
        service.getWorkflow(mockOrganizationId, created.id),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException when workflow has pending requests', async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'With Requests',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverUserIds: [mockUserId] }],
      });

      // Create an approval request
      await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-123',
      });

      await expect(
        service.deleteWorkflow(mockOrganizationId, workflow.id),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('listWorkflows', () => {
    beforeEach(async () => {
      // Create some test workflows
      await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Policy Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverRoles: ['admin'] }],
        isActive: true,
      });
      await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Control Workflow',
        entityType: WorkflowEntityType.Control,
        steps: [{ name: 'Step', order: 1, approverRoles: ['admin'] }],
        isActive: false,
      });
    });

    it('should return paginated list of workflows', async () => {
      const result = await service.listWorkflows(mockOrganizationId, {});

      expect(result.data.length).toBeGreaterThanOrEqual(2);
      expect(result.meta).toBeDefined();
      expect(result.meta.total).toBeGreaterThanOrEqual(2);
    });

    it('should filter by entityType', async () => {
      const result = await service.listWorkflows(mockOrganizationId, {
        entityType: WorkflowEntityType.Policy,
      });

      expect(result.data.every(w => w.entityType === WorkflowEntityType.Policy)).toBe(true);
    });

    it('should filter by activeOnly', async () => {
      const result = await service.listWorkflows(mockOrganizationId, {
        activeOnly: true,
      });

      expect(result.data.every(w => w.isActive)).toBe(true);
    });
  });

  // ==================== Approval Request Tests ====================

  describe('createApprovalRequest', () => {
    let workflowId: string;

    beforeEach(async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Test Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [
          { name: 'Step 1', order: 1, approverUserIds: [mockUserId], timeoutHours: 24 },
          { name: 'Step 2', order: 2, approverRoles: ['admin'] },
        ],
      });
      workflowId = workflow.id;
    });

    it('should create an approval request', async () => {
      const dto: CreateApprovalRequestDto = {
        workflowId,
        entityId: 'policy-123',
        comment: 'Please approve this policy',
      };

      const result = await service.createApprovalRequest(mockOrganizationId, mockUserId, dto);

      expect(result.id).toBeDefined();
      expect(result.workflowId).toBe(workflowId);
      expect(result.entityId).toBe('policy-123');
      expect(result.status).toBe(ApprovalRequestStatus.Pending);
      expect(result.currentStep).toBe(1);
      expect(result.stepApprovals).toHaveLength(2);
    });

    it('should set expiration based on timeout', async () => {
      const result = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId,
        entityId: 'entity-456',
      });

      expect(result.expiresAt).toBeDefined();
      expect(new Date(result.expiresAt!).getTime()).toBeGreaterThan(Date.now());
    });

    it('should throw NotFoundException for non-existent workflow', async () => {
      await expect(
        service.createApprovalRequest(mockOrganizationId, mockUserId, {
          workflowId: 'nonexistent',
          entityId: 'entity-789',
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for inactive workflow', async () => {
      await service.updateWorkflow(mockOrganizationId, workflowId, { isActive: false });

      await expect(
        service.createApprovalRequest(mockOrganizationId, mockUserId, {
          workflowId,
          entityId: 'entity-new',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for duplicate pending request', async () => {
      await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId,
        entityId: 'entity-dup',
      });

      await expect(
        service.createApprovalRequest(mockOrganizationId, mockUserId, {
          workflowId,
          entityId: 'entity-dup',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('approveOrReject', () => {
    let workflowId: string;
    let requestId: string;

    beforeEach(async () => {
      // Create workflow with current user as approver
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Approval Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [
          { name: 'Step 1', order: 1, approverUserIds: [mockUserId] },
          { name: 'Step 2', order: 2, approverUserIds: ['other-user'] },
        ],
      });
      workflowId = workflow.id;

      // Mock user lookup for permission checks
      mockUserFindUnique.mockResolvedValue({
        id: mockUserId,
        role: 'admin',
      });
      mockMembershipFindMany.mockResolvedValue([]);

      // Create approval request
      const request = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId,
        entityId: 'entity-approve',
      });
      requestId = request.id;
    });

    it('should approve first step and advance to next', async () => {
      const dto: ApprovalActionDto = {
        action: 'approve',
        comment: 'Looks good',
      };

      const result = await service.approveOrReject(mockOrganizationId, mockUserId, requestId, dto);

      expect(result.status).toBe(ApprovalRequestStatus.InProgress);
      expect(result.currentStep).toBe(2);
      expect(result.stepApprovals[0].status).toBe('approved');
      expect(result.stepApprovals[0].comment).toBe('Looks good');
    });

    it('should reject request immediately on rejection', async () => {
      const dto: ApprovalActionDto = {
        action: 'reject',
        comment: 'Needs changes',
      };

      const result = await service.approveOrReject(mockOrganizationId, mockUserId, requestId, dto);

      expect(result.status).toBe(ApprovalRequestStatus.Rejected);
      expect(result.completedAt).toBeDefined();
      expect(result.stepApprovals[0].status).toBe('rejected');
    });

    it('should complete workflow when all steps approved', async () => {
      // For this test, create a single-step workflow
      const workflow2 = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Single Step Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [
          { name: 'Only Step', order: 1, approverUserIds: [mockUserId] },
        ],
      });

      const request2 = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow2.id,
        entityId: 'entity-single',
      });

      const result = await service.approveOrReject(mockOrganizationId, mockUserId, request2.id, {
        action: 'approve',
      });

      expect(result.status).toBe(ApprovalRequestStatus.Approved);
      expect(result.completedAt).toBeDefined();
    });

    it('should throw ForbiddenException when user cannot approve', async () => {
      mockUserFindUnique.mockResolvedValue({
        id: 'unauthorized-user',
        role: 'viewer',
      });
      mockMembershipFindMany.mockResolvedValue([]);

      await expect(
        service.approveOrReject(mockOrganizationId, 'unauthorized-user', requestId, {
          action: 'approve',
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw BadRequestException for already completed request', async () => {
      // Reject the request first
      await service.approveOrReject(mockOrganizationId, mockUserId, requestId, {
        action: 'reject',
      });

      await expect(
        service.approveOrReject(mockOrganizationId, mockUserId, requestId, {
          action: 'approve',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('cancelRequest', () => {
    let requestId: string;

    beforeEach(async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Cancel Test Workflow',
        entityType: WorkflowEntityType.Control,
        steps: [{ name: 'Step', order: 1, approverUserIds: [mockUserId] }],
      });

      const request = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-cancel',
      });
      requestId = request.id;
    });

    it('should cancel a pending request', async () => {
      await service.cancelRequest(mockOrganizationId, mockUserId, requestId);

      const result = await service.getApprovalRequest(mockOrganizationId, requestId);
      expect(result.status).toBe(ApprovalRequestStatus.Cancelled);
      expect(result.completedAt).toBeDefined();
    });

    it('should throw ForbiddenException when not the requester', async () => {
      await expect(
        service.cancelRequest(mockOrganizationId, 'other-user', requestId),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw BadRequestException for already completed request', async () => {
      mockUserFindUnique.mockResolvedValue({
        id: mockUserId,
        role: 'admin',
      });

      // Approve the request first
      await service.approveOrReject(mockOrganizationId, mockUserId, requestId, {
        action: 'approve',
      });

      // Then fetch current status to verify (single-step workflow = approved)
      const request = await service.getApprovalRequest(mockOrganizationId, requestId);
      expect(request.status).toBe(ApprovalRequestStatus.Approved);

      await expect(
        service.cancelRequest(mockOrganizationId, mockUserId, requestId),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('listApprovalRequests', () => {
    beforeEach(async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'List Test Workflow',
        entityType: WorkflowEntityType.Vendor,
        steps: [{ name: 'Step', order: 1, approverUserIds: [mockUserId] }],
      });

      // Create multiple requests
      await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-1',
      });
      await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-2',
      });
      await service.createApprovalRequest(mockOrganizationId, 'other-user', {
        workflowId: workflow.id,
        entityId: 'entity-3',
      });
    });

    it('should return paginated list of requests', async () => {
      const result = await service.listApprovalRequests(mockOrganizationId, mockUserId, {});

      expect(result.data.length).toBeGreaterThanOrEqual(3);
    });

    it('should filter by status', async () => {
      const result = await service.listApprovalRequests(mockOrganizationId, mockUserId, {
        status: ApprovalRequestStatus.Pending,
      });

      expect(result.data.every(r => r.status === ApprovalRequestStatus.Pending)).toBe(true);
    });

    it('should filter by myRequests', async () => {
      const result = await service.listApprovalRequests(mockOrganizationId, mockUserId, {
        myRequests: true,
      });

      expect(result.data.every(r => r.requestedBy === mockUserId)).toBe(true);
    });

    it('should filter by pendingMyApproval', async () => {
      mockUserFindUnique.mockResolvedValue({
        id: mockUserId,
        role: 'admin',
      });
      mockMembershipFindMany.mockResolvedValue([]);

      const result = await service.listApprovalRequests(mockOrganizationId, mockUserId, {
        pendingMyApproval: true,
      });

      // Should only return requests where current user can approve
      expect(result.data.length).toBeGreaterThan(0);
    });
  });

  describe('canUserApproveStep', () => {
    it('should allow user when in approverUserIds', async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'User Approver Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverUserIds: [mockUserId] }],
      });

      const request = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-user-approver',
      });

      // If user can approve, this should succeed
      mockUserFindUnique.mockResolvedValue({
        id: mockUserId,
        role: 'viewer',
      });

      const result = await service.approveOrReject(mockOrganizationId, mockUserId, request.id, {
        action: 'approve',
      });

      expect(result.status).toBe(ApprovalRequestStatus.Approved);
    });

    it('should allow user when role matches approverRoles', async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Role Approver Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverRoles: ['compliance_manager'] }],
      });

      const request = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-role-approver',
      });

      // User has the matching role
      mockUserFindUnique.mockResolvedValue({
        id: 'role-user',
        role: 'compliance_manager',
      });
      mockMembershipFindMany.mockResolvedValue([]);

      const result = await service.approveOrReject(mockOrganizationId, 'role-user', request.id, {
        action: 'approve',
      });

      expect(result.status).toBe(ApprovalRequestStatus.Approved);
    });

    it('should allow user when in a matching permission group', async () => {
      const workflow = await service.createWorkflow(mockOrganizationId, mockUserId, {
        name: 'Group Approver Workflow',
        entityType: WorkflowEntityType.Policy,
        steps: [{ name: 'Step', order: 1, approverGroupIds: ['group-approvers'] }],
      });

      const request = await service.createApprovalRequest(mockOrganizationId, mockUserId, {
        workflowId: workflow.id,
        entityId: 'entity-group-approver',
      });

      // User is in the matching group
      mockUserFindUnique.mockResolvedValue({
        id: 'group-user',
        role: 'viewer',
      });
      mockMembershipFindMany.mockResolvedValue([
        { userId: 'group-user', groupId: 'group-approvers' },
      ]);

      const result = await service.approveOrReject(mockOrganizationId, 'group-user', request.id, {
        action: 'approve',
      });

      expect(result.status).toBe(ApprovalRequestStatus.Approved);
    });
  });
});
