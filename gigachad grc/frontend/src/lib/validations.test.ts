import { describe, it, expect } from 'vitest';
import {
  controlSchema,
  riskSchema,
  policySchema,
  vendorSchema,
  contractSchema,
  frameworkSchema,
} from './validations';

describe('Validation Schemas', () => {
  describe('controlSchema', () => {
    it('validates a valid control', () => {
      const validControl = {
        controlId: 'AC-001',
        title: 'Access Control Policy',
        description: 'This control ensures proper access management.',
        category: 'access_control',
      };
      
      const result = controlSchema.safeParse(validControl);
      expect(result.success).toBe(true);
    });

    it('requires controlId', () => {
      const invalidControl = {
        title: 'Test Control',
        description: 'Test description',
        category: 'access_control',
      };
      
      const result = controlSchema.safeParse(invalidControl);
      expect(result.success).toBe(false);
    });

    it('validates controlId format', () => {
      const invalidControl = {
        controlId: 'invalid-format',  // Should be XX-000
        title: 'Test Control',
        description: 'Test description',
        category: 'access_control',
      };
      
      const result = controlSchema.safeParse(invalidControl);
      expect(result.success).toBe(false);
    });

    it('requires category', () => {
      const invalidControl = {
        controlId: 'AC-001',
        title: 'Test Control',
        description: 'Test description',
      };
      
      const result = controlSchema.safeParse(invalidControl);
      expect(result.success).toBe(false);
    });

    it('allows optional fields', () => {
      const validControl = {
        controlId: 'AC-001',
        title: 'Access Control Policy',
        description: 'This control ensures proper access management.',
        category: 'access_control',
        subcategory: 'authentication',
        tags: ['critical', 'pci'],
        guidance: 'Additional guidance text here.',
        automationSupported: true,
      };
      
      const result = controlSchema.safeParse(validControl);
      expect(result.success).toBe(true);
    });
  });

  describe('riskSchema', () => {
    it('validates a valid risk', () => {
      const validRisk = {
        title: 'Data Breach Risk',
        description: 'Risk of unauthorized access to customer data.',
      };
      
      const result = riskSchema.safeParse(validRisk);
      expect(result.success).toBe(true);
    });

    it('requires title', () => {
      const invalidRisk = {
        description: 'Test description for the risk.',
      };
      
      const result = riskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('requires description', () => {
      const invalidRisk = {
        title: 'Test Risk',
      };
      
      const result = riskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('validates likelihood enum values', () => {
      const invalidRisk = {
        title: 'Data Breach Risk',
        description: 'Risk of unauthorized access.',
        likelihood: 'invalid_value',
      };
      
      const result = riskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('validates impact enum values', () => {
      const invalidRisk = {
        title: 'Data Breach Risk',
        description: 'Risk of unauthorized access.',
        impact: 'invalid_value',
      };
      
      const result = riskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('accepts valid likelihood and impact', () => {
      const validRisk = {
        title: 'Data Breach Risk',
        description: 'Risk of unauthorized access.',
        likelihood: 'likely',
        impact: 'major',
      };
      
      const result = riskSchema.safeParse(validRisk);
      expect(result.success).toBe(true);
    });
  });

  describe('policySchema', () => {
    it('validates a valid policy', () => {
      const validPolicy = {
        title: 'Information Security Policy',
        category: 'information_security',
        ownerId: 'user-123',
      };
      
      const result = policySchema.safeParse(validPolicy);
      expect(result.success).toBe(true);
    });

    it('requires title', () => {
      const invalidPolicy = {
        category: 'information_security',
        ownerId: 'user-123',
      };
      
      const result = policySchema.safeParse(invalidPolicy);
      expect(result.success).toBe(false);
    });

    it('requires category', () => {
      const invalidPolicy = {
        title: 'Test Policy',
        ownerId: 'user-123',
      };
      
      const result = policySchema.safeParse(invalidPolicy);
      expect(result.success).toBe(false);
    });

    it('requires ownerId', () => {
      const invalidPolicy = {
        title: 'Test Policy',
        category: 'information_security',
      };
      
      const result = policySchema.safeParse(invalidPolicy);
      expect(result.success).toBe(false);
    });

    it('validates review frequency enum', () => {
      const invalidPolicy = {
        title: 'Test Policy Title',
        category: 'information_security',
        ownerId: 'user-123',
        reviewFrequency: 'every_day',  // Invalid value
      };
      
      const result = policySchema.safeParse(invalidPolicy);
      expect(result.success).toBe(false);
    });

    it('accepts valid review frequency', () => {
      const validPolicy = {
        title: 'Test Policy Title',
        category: 'information_security',
        ownerId: 'user-123',
        reviewFrequency: 'quarterly',
      };
      
      const result = policySchema.safeParse(validPolicy);
      expect(result.success).toBe(true);
    });
  });

  describe('vendorSchema', () => {
    it('validates a valid vendor', () => {
      const validVendor = {
        name: 'Acme Security Inc',
      };
      
      const result = vendorSchema.safeParse(validVendor);
      expect(result.success).toBe(true);
    });

    it('validates vendor with optional fields', () => {
      const validVendor = {
        name: 'Acme Security Inc',
        tier: 'tier_1',
        category: 'software_vendor',
        criticality: 'high',
      };
      
      const result = vendorSchema.safeParse(validVendor);
      expect(result.success).toBe(true);
    });

    it('requires name', () => {
      const invalidVendor = {
        tier: 'tier_1',
      };
      
      const result = vendorSchema.safeParse(invalidVendor);
      expect(result.success).toBe(false);
    });

    it('validates tier enum', () => {
      const invalidVendor = {
        name: 'Acme Security Inc',
        tier: 'super_critical',  // Invalid - should be tier_1, tier_2, etc.
      };
      
      const result = vendorSchema.safeParse(invalidVendor);
      expect(result.success).toBe(false);
    });

    it('validates criticality enum', () => {
      const invalidVendor = {
        name: 'Acme Security Inc',
        criticality: 'super_high',  // Invalid
      };
      
      const result = vendorSchema.safeParse(invalidVendor);
      expect(result.success).toBe(false);
    });
  });

  describe('contractSchema', () => {
    it('validates a valid contract', () => {
      const validContract = {
        vendorId: 'vendor-123',
        title: 'Security Services Agreement',
        startDate: '2024-01-01',
      };
      
      const result = contractSchema.safeParse(validContract);
      expect(result.success).toBe(true);
    });

    it('validates contract with optional fields', () => {
      const validContract = {
        vendorId: 'vendor-123',
        title: 'Security Services Agreement',
        startDate: '2024-01-01',
        endDate: '2025-01-01',
        value: 50000,
        status: 'active',
      };
      
      const result = contractSchema.safeParse(validContract);
      expect(result.success).toBe(true);
    });

    it('requires vendorId', () => {
      const invalidContract = {
        title: 'Test Contract',
        startDate: '2024-01-01',
      };
      
      const result = contractSchema.safeParse(invalidContract);
      expect(result.success).toBe(false);
    });

    it('requires title', () => {
      const invalidContract = {
        vendorId: 'vendor-123',
        startDate: '2024-01-01',
      };
      
      const result = contractSchema.safeParse(invalidContract);
      expect(result.success).toBe(false);
    });

    it('requires startDate', () => {
      const invalidContract = {
        vendorId: 'vendor-123',
        title: 'Test Contract',
      };
      
      const result = contractSchema.safeParse(invalidContract);
      expect(result.success).toBe(false);
    });

    it('validates status enum', () => {
      const invalidContract = {
        vendorId: 'vendor-123',
        title: 'Test Contract',
        startDate: '2024-01-01',
        status: 'invalid_status',
      };
      
      const result = contractSchema.safeParse(invalidContract);
      expect(result.success).toBe(false);
    });
  });

  describe('frameworkSchema', () => {
    it('validates a valid framework', () => {
      const validFramework = {
        name: 'SOC 2 Type II',
        type: 'soc2',
      };
      
      const result = frameworkSchema.safeParse(validFramework);
      expect(result.success).toBe(true);
    });

    it('validates framework with optional fields', () => {
      const validFramework = {
        name: 'SOC 2 Type II',
        type: 'soc2',
        version: '2017',
        description: 'Service Organization Control 2 framework.',
        isActive: true,
      };
      
      const result = frameworkSchema.safeParse(validFramework);
      expect(result.success).toBe(true);
    });

    it('requires name', () => {
      const invalidFramework = {
        type: 'soc2',
      };
      
      const result = frameworkSchema.safeParse(invalidFramework);
      expect(result.success).toBe(false);
    });

    it('requires type', () => {
      const invalidFramework = {
        name: 'SOC 2 Type II',
      };
      
      const result = frameworkSchema.safeParse(invalidFramework);
      expect(result.success).toBe(false);
    });

    it('validates type enum', () => {
      const invalidFramework = {
        name: 'Custom Framework',
        type: 'invalid_type',
      };
      
      const result = frameworkSchema.safeParse(invalidFramework);
      expect(result.success).toBe(false);
    });
  });
});
