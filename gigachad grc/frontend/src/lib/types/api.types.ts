/**
 * Core API Type Definitions
 * 
 * This file contains strongly-typed interfaces for API responses
 * to replace `any` types throughout the application.
 */

// ===========================================
// Common Types
// ===========================================

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface ApiError {
  message: string | string[];
  error?: string;
  statusCode: number;
}

export type Status = 'active' | 'inactive' | 'pending' | 'archived';

// ===========================================
// Control Types
// ===========================================

export type ControlStatus = 
  | 'not_started'
  | 'in_progress'
  | 'implemented'
  | 'not_applicable';

export interface ControlListItem {
  id: string;
  controlId: string;
  title: string;
  category: string;
  isCustom: boolean;
  status: ControlStatus;
  evidenceCount: number;
}

export interface ControlDetail extends ControlListItem {
  description: string;
  guidance?: string;
  subcategory?: string;
  tags: string[];
  automationSupported: boolean;
  frameworks: FrameworkMapping[];
  implementation?: ControlImplementation;
  createdAt: string;
  updatedAt: string;
}

export interface ControlImplementation {
  id: string;
  status: ControlStatus;
  notes?: string;
  evidence: string[];
  testingFrequency: string;
  lastTestedAt?: string;
  nextTestDue?: string;
  ownerId?: string;
  ownerName?: string;
}

export interface FrameworkMapping {
  frameworkId: string;
  frameworkName: string;
  requirementId: string;
  requirementCode: string;
}

// ===========================================
// Risk Types
// ===========================================

export type RiskStatus = 
  | 'risk_identified'
  | 'not_a_risk'
  | 'actual_risk'
  | 'risk_analysis_in_progress'
  | 'risk_analyzed'
  | 'open'
  | 'in_treatment'
  | 'accepted'
  | 'mitigated'
  | 'closed';

export type RiskLevel = 
  | 'very_low'
  | 'low'
  | 'medium'
  | 'high'
  | 'very_high'
  | 'critical';

export type Likelihood = 
  | 'rare'
  | 'unlikely'
  | 'possible'
  | 'likely'
  | 'almost_certain';

export type Impact = 
  | 'negligible'
  | 'minor'
  | 'moderate'
  | 'major'
  | 'severe';

export interface RiskListItem {
  id: string;
  riskId: string;
  title: string;
  category: string;
  status: RiskStatus;
  inherentRisk?: RiskLevel;
  residualRisk?: RiskLevel;
  controlCount: number;
  assetCount: number;
}

export interface RiskDetail extends RiskListItem {
  description: string;
  likelihood?: Likelihood;
  impact?: Impact;
  likelihoodPct?: number;
  impactValue?: number;
  annualLossExp?: number;
  treatmentPlan?: string;
  ownerId?: string;
  ownerName?: string;
  reviewFrequency?: string;
  lastReviewedAt?: string;
  nextReviewDue?: string;
  tags: string[];
  assets: AssetLink[];
  controls: ControlLink[];
  scenarios: RiskScenario[];
  createdAt: string;
  updatedAt: string;
}

export interface AssetLink {
  id: string;
  name: string;
  type: string;
}

export interface ControlLink {
  id: string;
  controlId: string;
  title: string;
  effectiveness?: string;
}

export interface RiskScenario {
  id: string;
  name: string;
  description?: string;
  probability?: number;
  impact?: number;
}

// ===========================================
// Evidence Types
// ===========================================

export type EvidenceType = 
  | 'screenshot'
  | 'document'
  | 'export'
  | 'report'
  | 'configuration'
  | 'log';

export type EvidenceStatus = 
  | 'pending_review'
  | 'approved'
  | 'rejected'
  | 'expired';

export interface EvidenceListItem {
  id: string;
  title: string;
  type: EvidenceType;
  status: EvidenceStatus;
  fileUrl?: string;
  fileName?: string;
  fileSize?: number;
  mimeType?: string;
  validFrom?: string;
  validUntil?: string;
  isExpired: boolean;
  linkedControlIds: string[];
  createdAt: string;
}

export interface EvidenceDetail extends EvidenceListItem {
  description?: string;
  uploadedBy?: string;
  uploadedByName?: string;
  reviewedBy?: string;
  reviewedByName?: string;
  reviewedAt?: string;
  reviewNotes?: string;
  tags: string[];
  linkedControls: ControlLink[];
  updatedAt: string;
}

// ===========================================
// Vendor Types
// ===========================================

export type VendorStatus = 
  | 'active'
  | 'pending_review'
  | 'in_review'
  | 'approved'
  | 'rejected'
  | 'offboarded';

export type VendorCriticality = 
  | 'critical'
  | 'high'
  | 'medium'
  | 'low';

export interface VendorListItem {
  id: string;
  name: string;
  category?: string;
  status: VendorStatus;
  criticality?: VendorCriticality;
  riskScore?: number;
  tier?: string;
}

export interface VendorDetail extends VendorListItem {
  description?: string;
  website?: string;
  contactName?: string;
  contactEmail?: string;
  contactPhone?: string;
  contractStartDate?: string;
  contractEndDate?: string;
  contractValue?: number;
  dataAccess: string[];
  certifications: string[];
  tags: string[];
  assessments: VendorAssessmentSummary[];
  createdAt: string;
  updatedAt: string;
}

export interface VendorAssessmentSummary {
  id: string;
  assessmentDate: string;
  score?: number;
  status: string;
}

// ===========================================
// Dashboard Types
// ===========================================

export interface DashboardSummary {
  complianceScore: {
    overall: number;
    byFramework: FrameworkScore[];
  };
  controls: {
    total: number;
    byStatus: Record<ControlStatus, number>;
    overdue: number;
  };
  evidence: {
    total: number;
    pendingReview: number;
    expiringSoon: number;
    expired: number;
  };
  upcomingTests: UpcomingTest[];
  recentActivity: ActivityItem[];
}

export interface FrameworkScore {
  frameworkId: string;
  name: string;
  score: number;
}

export interface UpcomingTest {
  controlId: string;
  controlTitle: string;
  dueDate: string;
  daysUntilDue: number;
}

export interface ActivityItem {
  id: string;
  action: string;
  entityType: string;
  entityId: string;
  entityName: string;
  userId: string;
  userName: string;
  timestamp: string;
}

// ===========================================
// Framework Types
// ===========================================

export interface FrameworkListItem {
  id: string;
  name: string;
  version?: string;
  type: string;
  isActive: boolean;
  controlCount: number;
  readiness?: {
    score: number;
    implemented: number;
    total: number;
  };
}

export interface FrameworkDetail extends FrameworkListItem {
  description?: string;
  publisher?: string;
  effectiveDate?: string;
  requirements: FrameworkRequirement[];
  createdAt: string;
  updatedAt: string;
}

export interface FrameworkRequirement {
  id: string;
  code: string;
  title: string;
  description?: string;
  category?: string;
  parentId?: string;
  mappedControlIds: string[];
}

// ===========================================
// Policy Types
// ===========================================

export type PolicyStatus = 
  | 'draft'
  | 'in_review'
  | 'approved'
  | 'published'
  | 'archived';

export interface PolicyListItem {
  id: string;
  title: string;
  category?: string;
  status: PolicyStatus;
  version?: string;
  ownerId?: string;
  ownerName?: string;
  publishedAt?: string;
  nextReviewDate?: string;
}

export interface PolicyDetail extends PolicyListItem {
  content?: string;
  summary?: string;
  effectiveDate?: string;
  tags: string[];
  linkedControlIds: string[];
  approvals: PolicyApproval[];
  revisions: PolicyRevision[];
  createdAt: string;
  updatedAt: string;
}

export interface PolicyApproval {
  id: string;
  approverId: string;
  approverName: string;
  status: 'pending' | 'approved' | 'rejected';
  comments?: string;
  timestamp: string;
}

export interface PolicyRevision {
  id: string;
  version: string;
  changes?: string;
  createdBy: string;
  createdByName: string;
  createdAt: string;
}

// ===========================================
// User Types
// ===========================================

export type UserRole = 
  | 'admin'
  | 'compliance_manager'
  | 'auditor'
  | 'risk_manager'
  | 'viewer';

export interface UserListItem {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  role: UserRole;
  isActive: boolean;
  lastLoginAt?: string;
}

export interface UserDetail extends UserListItem {
  organizationId: string;
  permissions: string[];
  createdAt: string;
  updatedAt: string;
}

// ===========================================
// Notification Types
// ===========================================

export type NotificationLevel = 'info' | 'success' | 'warning' | 'error';

export interface Notification {
  id: string;
  title: string;
  message: string;
  level: NotificationLevel;
  isRead: boolean;
  link?: string;
  createdAt: string;
}

// ===========================================
// Audit Types
// ===========================================

export interface AuditLogEntry {
  id: string;
  action: string;
  entityType: string;
  entityId: string;
  entityName?: string;
  userId: string;
  userName?: string;
  userEmail?: string;
  description?: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: string;
}

