import { IsString, IsOptional, IsBoolean, IsDateString, IsEnum } from 'class-validator';

// Task types for different workflow stages
export enum RiskWorkflowTaskType {
  VALIDATE = 'validate',
  ASSESS = 'assess',
  REVIEW_ASSESSMENT = 'review_assessment',
  TREATMENT_DECISION = 'treatment_decision',
  EXECUTIVE_APPROVAL = 'executive_approval',
  MITIGATION_UPDATE = 'mitigation_update',
  CUSTOM = 'custom',
}

// Task statuses
export enum RiskWorkflowTaskStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
  REASSIGNED = 'reassigned',
}

// Task priorities
export enum RiskWorkflowTaskPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

// Workflow stages
export enum RiskWorkflowStage {
  INTAKE = 'intake',
  ASSESSMENT = 'assessment',
  TREATMENT = 'treatment',
}

// DTO for creating a manual task
export class CreateRiskWorkflowTaskDto {
  @IsString()
  @IsEnum(RiskWorkflowTaskType)
  taskType: RiskWorkflowTaskType;

  @IsString()
  title: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsString()
  assigneeId: string;

  @IsOptional()
  @IsEnum(RiskWorkflowTaskPriority)
  priority?: RiskWorkflowTaskPriority;

  @IsOptional()
  @IsDateString()
  dueDate?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  @IsEnum(RiskWorkflowStage)
  workflowStage?: RiskWorkflowStage;
}

// DTO for updating a task
export class UpdateRiskWorkflowTaskDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsEnum(RiskWorkflowTaskPriority)
  priority?: RiskWorkflowTaskPriority;

  @IsOptional()
  @IsDateString()
  dueDate?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}

// DTO for reassigning a task
export class ReassignTaskDto {
  @IsString()
  newAssigneeId: string;

  @IsOptional()
  @IsString()
  reason?: string;
}

// DTO for completing a task
export class CompleteTaskDto {
  @IsOptional()
  @IsString()
  completionNotes?: string;

  @IsOptional()
  @IsString()
  resultingAction?: string; // approved, rejected, revised, etc.
}

// DTO for filtering tasks
export class RiskWorkflowTaskFilterDto {
  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  taskType?: string;

  @IsOptional()
  @IsString()
  priority?: string;

  @IsOptional()
  @IsString()
  assigneeId?: string;

  @IsOptional()
  @IsString()
  workflowStage?: string;

  @IsOptional()
  @IsBoolean()
  overdue?: boolean;
}

// Response DTO for a task
export interface RiskWorkflowTaskResponseDto {
  id: string;
  riskId: string;
  taskType: string;
  title: string;
  description?: string;
  assigneeId: string;
  assignedById: string;
  assignedAt: Date;
  status: string;
  priority: string;
  dueDate?: Date;
  startedAt?: Date;
  completedAt?: Date;
  completedById?: string;
  workflowStage: string;
  previousStatus?: string;
  resultingAction?: string;
  notes?: string;
  completionNotes?: string;
  isAutoCreated: boolean;
  createdAt: Date;
  updatedAt: Date;
  // Joined data
  risk?: {
    id: string;
    riskId: string;
    title: string;
    inherentRisk?: string;
    status: string;
  };
  assignee?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
  };
  assignedBy?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
  };
}

// Configuration for auto-creating tasks
export interface AutoCreateTaskConfig {
  taskType: RiskWorkflowTaskType;
  title: string;
  description: string;
  workflowStage: RiskWorkflowStage;
  defaultPriority: RiskWorkflowTaskPriority;
  dueDaysFromNow?: number;
}

// Map of workflow transitions to task configurations
export const WORKFLOW_TASK_CONFIGS: Record<string, AutoCreateTaskConfig> = {
  // When risk is validated, create assessment task
  risk_validated: {
    taskType: RiskWorkflowTaskType.ASSESS,
    title: 'Complete Risk Assessment',
    description: 'Analyze the risk, determine likelihood and impact, and recommend treatment approach.',
    workflowStage: RiskWorkflowStage.ASSESSMENT,
    defaultPriority: RiskWorkflowTaskPriority.MEDIUM,
    dueDaysFromNow: 14,
  },
  // When assessment is submitted, create GRC review task
  assessment_submitted: {
    taskType: RiskWorkflowTaskType.REVIEW_ASSESSMENT,
    title: 'Review Risk Assessment',
    description: 'Review the submitted assessment and approve or request revisions.',
    workflowStage: RiskWorkflowStage.ASSESSMENT,
    defaultPriority: RiskWorkflowTaskPriority.HIGH,
    dueDaysFromNow: 7,
  },
  // When assessment is approved, create treatment decision task
  assessment_approved: {
    taskType: RiskWorkflowTaskType.TREATMENT_DECISION,
    title: 'Make Treatment Decision',
    description: 'Decide how to treat this risk: mitigate, accept, transfer, or avoid.',
    workflowStage: RiskWorkflowStage.TREATMENT,
    defaultPriority: RiskWorkflowTaskPriority.HIGH,
    dueDaysFromNow: 14,
  },
  // When executive approval is needed
  executive_approval_needed: {
    taskType: RiskWorkflowTaskType.EXECUTIVE_APPROVAL,
    title: 'Executive Approval Required',
    description: 'Review and approve or deny the proposed risk treatment decision.',
    workflowStage: RiskWorkflowStage.TREATMENT,
    defaultPriority: RiskWorkflowTaskPriority.CRITICAL,
    dueDaysFromNow: 7,
  },
  // When mitigation is in progress
  mitigation_started: {
    taskType: RiskWorkflowTaskType.MITIGATION_UPDATE,
    title: 'Update Mitigation Progress',
    description: 'Provide regular updates on mitigation progress and completion status.',
    workflowStage: RiskWorkflowStage.TREATMENT,
    defaultPriority: RiskWorkflowTaskPriority.MEDIUM,
    dueDaysFromNow: 30,
  },
};
