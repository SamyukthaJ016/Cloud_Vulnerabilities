// Employee Compliance - Standardized Evidence Type Keys
// These keys are used by the correlation engine to match data from any integration
// that provides employee-related evidence

/**
 * HRIS / HR Systems Evidence Types
 * Any integration providing these types will feed into the CorrelatedEmployee records
 */
export const HRIS_EVIDENCE_TYPES = {
  // Primary employee roster - REQUIRED for employee correlation
  EMPLOYEE_ROSTER: 'employee_roster',
  // Organizational hierarchy data
  ORG_CHART: 'org_chart',
  // Employment status changes
  EMPLOYMENT_STATUS: 'employment_status',
  // Onboarding/offboarding tracking
  ONBOARDING_STATUS: 'onboarding_status',
  OFFBOARDING_STATUS: 'offboarding_status',
} as const;

/**
 * Background Check Evidence Types
 * Data from background check providers (Certn, Checkr, etc.)
 */
export const BACKGROUND_CHECK_EVIDENCE_TYPES = {
  // Main background check results
  BACKGROUND_CHECK_RESULTS: 'background_check_results',
  // Screening/verification status
  SCREENING_STATUS: 'screening_status',
  // Identity verification
  IDENTITY_VERIFICATION: 'identity_verification',
  // Criminal record checks
  CRIMINAL_RECORDS: 'criminal_records',
  // Employment verification
  EMPLOYMENT_VERIFICATION: 'employment_verification',
  // Education verification
  EDUCATION_VERIFICATION: 'education_verification',
} as const;

/**
 * LMS / Security Awareness Training Evidence Types
 * Data from KnowBe4, Proofpoint, and other training platforms
 */
export const LMS_EVIDENCE_TYPES = {
  // Training campaign assignments
  TRAINING_ASSIGNMENTS: 'training_assignments',
  // Training completion records
  TRAINING_COMPLETIONS: 'training_completions',
  // Phishing simulation test results
  PHISHING_TEST_RESULTS: 'phishing_test_results',
  // Overall security awareness score
  SECURITY_AWARENESS_SCORE: 'security_awareness_score',
  // Training campaign data
  TRAINING_CAMPAIGNS: 'training_campaigns',
  // User training status summary
  USER_TRAINING_STATUS: 'user_training_status',
} as const;

/**
 * MDM / Asset Management Evidence Types
 * Data from device management systems (Jamf, Intune, etc.)
 */
export const MDM_EVIDENCE_TYPES = {
  // Device inventory
  DEVICE_INVENTORY: 'device_inventory',
  // Device assignments to users
  DEVICE_ASSIGNMENTS: 'device_assignments',
  // Device compliance status
  DEVICE_COMPLIANCE: 'device_compliance',
  // Managed applications
  MANAGED_APPS: 'managed_apps',
} as const;

/**
 * Identity Provider / Access Management Evidence Types
 * Data from Okta, Azure AD, Google Workspace, etc.
 */
export const IDENTITY_EVIDENCE_TYPES = {
  // User access list - systems/apps user has access to
  USER_ACCESS_LIST: 'user_access_list',
  // Access review status
  ACCESS_REVIEW_STATUS: 'access_review_status',
  // App assignments
  APP_ASSIGNMENTS: 'app_assignments',
  // Group memberships
  GROUP_MEMBERSHIPS: 'group_memberships',
  // MFA status
  MFA_STATUS: 'mfa_status',
  // Login activity
  LOGIN_ACTIVITY: 'login_activity',
} as const;

/**
 * All employee compliance evidence types combined
 */
export const EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES = {
  ...HRIS_EVIDENCE_TYPES,
  ...BACKGROUND_CHECK_EVIDENCE_TYPES,
  ...LMS_EVIDENCE_TYPES,
  ...MDM_EVIDENCE_TYPES,
  ...IDENTITY_EVIDENCE_TYPES,
} as const;

/**
 * Expected data schema for each evidence type
 * Used for validation and correlation
 */
export interface EmployeeRosterRecord {
  email: string; // Primary correlation key
  firstName?: string;
  lastName?: string;
  department?: string;
  jobTitle?: string;
  managerEmail?: string;
  hireDate?: string;
  employmentStatus?: 'active' | 'terminated' | 'on_leave' | 'pending';
  employeeId?: string;
  location?: string;
  employmentType?: 'full_time' | 'part_time' | 'contractor' | 'intern';
}

export interface BackgroundCheckRecord {
  email: string;
  status: 'pending' | 'in_progress' | 'clear' | 'flagged' | 'expired';
  checkType?: string;
  initiatedAt?: string;
  completedAt?: string;
  expiresAt?: string;
  provider?: string;
  externalId?: string;
}

export interface TrainingRecord {
  email: string;
  courseName: string;
  courseId?: string;
  status: 'assigned' | 'in_progress' | 'completed' | 'overdue' | 'waived';
  assignedAt?: string;
  dueDate?: string;
  completedAt?: string;
  score?: number;
  isRequired?: boolean;
}

export interface PhishingTestResult {
  email: string;
  campaignName: string;
  campaignId?: string;
  sentAt: string;
  result: 'not_clicked' | 'clicked' | 'reported' | 'submitted_data';
  clickedAt?: string;
  reportedAt?: string;
}

export interface SecurityAwarenessScore {
  email: string;
  overallScore: number; // 0-100
  riskLevel?: 'low' | 'medium' | 'high';
  lastUpdated: string;
  trainingScore?: number;
  phishingScore?: number;
}

export interface DeviceAssignment {
  email: string;
  deviceType: 'laptop' | 'desktop' | 'phone' | 'tablet' | 'other';
  deviceName?: string;
  serialNumber?: string;
  model?: string;
  manufacturer?: string;
  osVersion?: string;
  isCompliant?: boolean;
  lastCheckIn?: string;
  assignedAt?: string;
}

export interface UserAccessRecord {
  email: string;
  systems: Array<{
    name: string;
    accessLevel?: string;
    lastAccessed?: string;
  }>;
  lastReviewDate?: string;
  reviewStatus?: 'pending' | 'approved' | 'action_required';
}

/**
 * Evidence type categories for UI grouping
 */
export const EVIDENCE_TYPE_CATEGORIES = {
  hris: {
    label: 'HR Systems (HRIS)',
    description: 'Employee roster and organizational data',
    evidenceTypes: Object.values(HRIS_EVIDENCE_TYPES),
  },
  background_check: {
    label: 'Background Check',
    description: 'Screening and verification results',
    evidenceTypes: Object.values(BACKGROUND_CHECK_EVIDENCE_TYPES),
  },
  lms: {
    label: 'Learning & Awareness',
    description: 'Training and security awareness data',
    evidenceTypes: Object.values(LMS_EVIDENCE_TYPES),
  },
  mdm: {
    label: 'Device Management',
    description: 'Device inventory and compliance',
    evidenceTypes: Object.values(MDM_EVIDENCE_TYPES),
  },
  identity: {
    label: 'Identity & Access',
    description: 'User access and authentication data',
    evidenceTypes: Object.values(IDENTITY_EVIDENCE_TYPES),
  },
} as const;

/**
 * Check if an evidence type is employee-compliance related
 */
export function isEmployeeComplianceEvidenceType(evidenceType: string): boolean {
  return Object.values(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES).includes(evidenceType as any);
}

/**
 * Get the category for an evidence type
 */
export function getEvidenceTypeCategory(evidenceType: string): string | null {
  for (const [category, config] of Object.entries(EVIDENCE_TYPE_CATEGORIES)) {
    if ((config.evidenceTypes as readonly string[]).includes(evidenceType)) {
      return category;
    }
  }
  return null;
}

