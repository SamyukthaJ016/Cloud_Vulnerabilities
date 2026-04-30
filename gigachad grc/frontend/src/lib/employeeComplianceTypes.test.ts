import { describe, it, expect } from 'vitest';
import {
  HRIS_EVIDENCE_TYPES,
  BACKGROUND_CHECK_EVIDENCE_TYPES,
  LMS_EVIDENCE_TYPES,
  MDM_EVIDENCE_TYPES,
  IDENTITY_EVIDENCE_TYPES,
  EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES,
  EVIDENCE_TYPE_CATEGORIES,
  isEmployeeComplianceEvidenceType,
  getEvidenceTypeCategory,
} from './employeeComplianceTypes';
import type {
  EmployeeRosterRecord,
  BackgroundCheckRecord,
  TrainingRecord,
  PhishingTestResult,
  SecurityAwarenessScore,
  DeviceAssignment,
  UserAccessRecord,
} from './employeeComplianceTypes';

describe('Employee Compliance Types Library', () => {
  describe('HRIS_EVIDENCE_TYPES', () => {
    it('has expected evidence types', () => {
      expect(HRIS_EVIDENCE_TYPES.EMPLOYEE_ROSTER).toBe('employee_roster');
      expect(HRIS_EVIDENCE_TYPES.ORG_CHART).toBe('org_chart');
      expect(HRIS_EVIDENCE_TYPES.EMPLOYMENT_STATUS).toBe('employment_status');
      expect(HRIS_EVIDENCE_TYPES.ONBOARDING_STATUS).toBe('onboarding_status');
      expect(HRIS_EVIDENCE_TYPES.OFFBOARDING_STATUS).toBe('offboarding_status');
    });
  });

  describe('BACKGROUND_CHECK_EVIDENCE_TYPES', () => {
    it('has expected evidence types', () => {
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.BACKGROUND_CHECK_RESULTS).toBe('background_check_results');
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.SCREENING_STATUS).toBe('screening_status');
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.IDENTITY_VERIFICATION).toBe('identity_verification');
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.CRIMINAL_RECORDS).toBe('criminal_records');
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.EMPLOYMENT_VERIFICATION).toBe('employment_verification');
      expect(BACKGROUND_CHECK_EVIDENCE_TYPES.EDUCATION_VERIFICATION).toBe('education_verification');
    });
  });

  describe('LMS_EVIDENCE_TYPES', () => {
    it('has expected evidence types', () => {
      expect(LMS_EVIDENCE_TYPES.TRAINING_ASSIGNMENTS).toBe('training_assignments');
      expect(LMS_EVIDENCE_TYPES.TRAINING_COMPLETIONS).toBe('training_completions');
      expect(LMS_EVIDENCE_TYPES.PHISHING_TEST_RESULTS).toBe('phishing_test_results');
      expect(LMS_EVIDENCE_TYPES.SECURITY_AWARENESS_SCORE).toBe('security_awareness_score');
      expect(LMS_EVIDENCE_TYPES.TRAINING_CAMPAIGNS).toBe('training_campaigns');
      expect(LMS_EVIDENCE_TYPES.USER_TRAINING_STATUS).toBe('user_training_status');
    });
  });

  describe('MDM_EVIDENCE_TYPES', () => {
    it('has expected evidence types', () => {
      expect(MDM_EVIDENCE_TYPES.DEVICE_INVENTORY).toBe('device_inventory');
      expect(MDM_EVIDENCE_TYPES.DEVICE_ASSIGNMENTS).toBe('device_assignments');
      expect(MDM_EVIDENCE_TYPES.DEVICE_COMPLIANCE).toBe('device_compliance');
      expect(MDM_EVIDENCE_TYPES.MANAGED_APPS).toBe('managed_apps');
    });
  });

  describe('IDENTITY_EVIDENCE_TYPES', () => {
    it('has expected evidence types', () => {
      expect(IDENTITY_EVIDENCE_TYPES.USER_ACCESS_LIST).toBe('user_access_list');
      expect(IDENTITY_EVIDENCE_TYPES.ACCESS_REVIEW_STATUS).toBe('access_review_status');
      expect(IDENTITY_EVIDENCE_TYPES.APP_ASSIGNMENTS).toBe('app_assignments');
      expect(IDENTITY_EVIDENCE_TYPES.GROUP_MEMBERSHIPS).toBe('group_memberships');
      expect(IDENTITY_EVIDENCE_TYPES.MFA_STATUS).toBe('mfa_status');
      expect(IDENTITY_EVIDENCE_TYPES.LOGIN_ACTIVITY).toBe('login_activity');
    });
  });

  describe('EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES', () => {
    it('combines all evidence types', () => {
      // Should contain all types from all categories
      expect(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES.EMPLOYEE_ROSTER).toBeDefined();
      expect(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES.BACKGROUND_CHECK_RESULTS).toBeDefined();
      expect(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES.TRAINING_ASSIGNMENTS).toBeDefined();
      expect(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES.DEVICE_INVENTORY).toBeDefined();
      expect(EMPLOYEE_COMPLIANCE_EVIDENCE_TYPES.USER_ACCESS_LIST).toBeDefined();
    });
  });

  describe('EVIDENCE_TYPE_CATEGORIES', () => {
    it('has all categories', () => {
      expect(EVIDENCE_TYPE_CATEGORIES.hris).toBeDefined();
      expect(EVIDENCE_TYPE_CATEGORIES.background_check).toBeDefined();
      expect(EVIDENCE_TYPE_CATEGORIES.lms).toBeDefined();
      expect(EVIDENCE_TYPE_CATEGORIES.mdm).toBeDefined();
      expect(EVIDENCE_TYPE_CATEGORIES.identity).toBeDefined();
    });

    it('each category has label and description', () => {
      Object.values(EVIDENCE_TYPE_CATEGORIES).forEach((category) => {
        expect(category.label).toBeDefined();
        expect(typeof category.label).toBe('string');
        expect(category.description).toBeDefined();
        expect(typeof category.description).toBe('string');
        expect(category.evidenceTypes).toBeDefined();
        expect(Array.isArray(category.evidenceTypes)).toBe(true);
      });
    });
  });

  describe('isEmployeeComplianceEvidenceType', () => {
    it('returns true for valid evidence types', () => {
      expect(isEmployeeComplianceEvidenceType('employee_roster')).toBe(true);
      expect(isEmployeeComplianceEvidenceType('background_check_results')).toBe(true);
      expect(isEmployeeComplianceEvidenceType('training_assignments')).toBe(true);
      expect(isEmployeeComplianceEvidenceType('device_inventory')).toBe(true);
      expect(isEmployeeComplianceEvidenceType('user_access_list')).toBe(true);
    });

    it('returns false for invalid evidence types', () => {
      expect(isEmployeeComplianceEvidenceType('invalid_type')).toBe(false);
      expect(isEmployeeComplianceEvidenceType('')).toBe(false);
      expect(isEmployeeComplianceEvidenceType('random_string')).toBe(false);
    });
  });

  describe('getEvidenceTypeCategory', () => {
    it('returns correct category for HRIS types', () => {
      expect(getEvidenceTypeCategory('employee_roster')).toBe('hris');
      expect(getEvidenceTypeCategory('org_chart')).toBe('hris');
    });

    it('returns correct category for background check types', () => {
      expect(getEvidenceTypeCategory('background_check_results')).toBe('background_check');
      expect(getEvidenceTypeCategory('criminal_records')).toBe('background_check');
    });

    it('returns correct category for LMS types', () => {
      expect(getEvidenceTypeCategory('training_assignments')).toBe('lms');
      expect(getEvidenceTypeCategory('phishing_test_results')).toBe('lms');
    });

    it('returns correct category for MDM types', () => {
      expect(getEvidenceTypeCategory('device_inventory')).toBe('mdm');
      expect(getEvidenceTypeCategory('device_compliance')).toBe('mdm');
    });

    it('returns correct category for identity types', () => {
      expect(getEvidenceTypeCategory('user_access_list')).toBe('identity');
      expect(getEvidenceTypeCategory('mfa_status')).toBe('identity');
    });

    it('returns null for unknown types', () => {
      expect(getEvidenceTypeCategory('invalid_type')).toBeNull();
      expect(getEvidenceTypeCategory('')).toBeNull();
    });
  });

  describe('Type Interfaces', () => {
    it('EmployeeRosterRecord has valid structure', () => {
      const record: EmployeeRosterRecord = {
        email: 'john.doe@example.com',
        firstName: 'John',
        lastName: 'Doe',
        department: 'Engineering',
        jobTitle: 'Software Engineer',
        managerEmail: 'jane.manager@example.com',
        hireDate: '2023-01-15',
        employmentStatus: 'active',
        employeeId: 'EMP001',
        location: 'San Francisco',
        employmentType: 'full_time',
      };

      expect(record.email).toBe('john.doe@example.com');
      expect(record.employmentStatus).toBe('active');
    });

    it('BackgroundCheckRecord has valid structure', () => {
      const record: BackgroundCheckRecord = {
        email: 'john.doe@example.com',
        status: 'clear',
        checkType: 'criminal',
        initiatedAt: '2023-01-10T10:00:00Z',
        completedAt: '2023-01-12T14:00:00Z',
        expiresAt: '2026-01-12T14:00:00Z',
        provider: 'Checkr',
        externalId: 'CHK-12345',
      };

      expect(record.email).toBe('john.doe@example.com');
      expect(record.status).toBe('clear');
    });

    it('TrainingRecord has valid structure', () => {
      const record: TrainingRecord = {
        email: 'john.doe@example.com',
        courseName: 'Security Awareness 101',
        courseId: 'SEC-101',
        status: 'completed',
        assignedAt: '2023-01-01T00:00:00Z',
        dueDate: '2023-02-01T00:00:00Z',
        completedAt: '2023-01-15T10:00:00Z',
        score: 95,
        isRequired: true,
      };

      expect(record.courseName).toBe('Security Awareness 101');
      expect(record.status).toBe('completed');
      expect(record.score).toBe(95);
    });

    it('PhishingTestResult has valid structure', () => {
      const result: PhishingTestResult = {
        email: 'john.doe@example.com',
        campaignName: 'Q1 Phishing Test',
        campaignId: 'PHISH-Q1-2024',
        sentAt: '2024-01-15T08:00:00Z',
        result: 'reported',
        reportedAt: '2024-01-15T08:05:00Z',
      };

      expect(result.campaignName).toBe('Q1 Phishing Test');
      expect(result.result).toBe('reported');
    });

    it('SecurityAwarenessScore has valid structure', () => {
      const score: SecurityAwarenessScore = {
        email: 'john.doe@example.com',
        overallScore: 85,
        riskLevel: 'low',
        lastUpdated: '2024-01-20T12:00:00Z',
        trainingScore: 90,
        phishingScore: 80,
      };

      expect(score.overallScore).toBe(85);
      expect(score.riskLevel).toBe('low');
    });

    it('DeviceAssignment has valid structure', () => {
      const device: DeviceAssignment = {
        email: 'john.doe@example.com',
        deviceType: 'laptop',
        deviceName: 'MacBook Pro 14"',
        serialNumber: 'C02XXXXX',
        model: 'MacBook Pro (14-inch, 2023)',
        manufacturer: 'Apple',
        osVersion: 'macOS 14.2',
        isCompliant: true,
        lastCheckIn: '2024-01-20T10:00:00Z',
        assignedAt: '2023-06-01T00:00:00Z',
      };

      expect(device.deviceType).toBe('laptop');
      expect(device.isCompliant).toBe(true);
    });

    it('UserAccessRecord has valid structure', () => {
      const access: UserAccessRecord = {
        email: 'john.doe@example.com',
        systems: [
          { name: 'GitHub', accessLevel: 'admin', lastAccessed: '2024-01-19T15:00:00Z' },
          { name: 'AWS Console', accessLevel: 'read-only', lastAccessed: '2024-01-18T10:00:00Z' },
        ],
        lastReviewDate: '2024-01-01T00:00:00Z',
        reviewStatus: 'approved',
      };

      expect(access.systems).toHaveLength(2);
      expect(access.reviewStatus).toBe('approved');
    });
  });
});
