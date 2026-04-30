import { describe, it, expect } from 'vitest';
import { INTEGRATION_TYPES, IntegrationType, ConfigField, EvidenceType } from './integrationTypes';

describe('Integration Types Library', () => {
  describe('INTEGRATION_TYPES', () => {
    it('has integration definitions', () => {
      expect(Object.keys(INTEGRATION_TYPES).length).toBeGreaterThan(0);
    });

    it('each integration has required properties', () => {
      Object.entries(INTEGRATION_TYPES).forEach(([_key, integration]: [string, IntegrationType]) => {
        expect(integration.name).toBeDefined();
        expect(typeof integration.name).toBe('string');
        expect(integration.name.length).toBeGreaterThan(0);

        expect(integration.description).toBeDefined();
        expect(typeof integration.description).toBe('string');

        expect(integration.category).toBeDefined();
        expect(typeof integration.category).toBe('string');

        expect(integration.iconSlug).toBeDefined();
        expect(typeof integration.iconSlug).toBe('string');

        expect(integration.authType).toBeDefined();
        expect(['api_key', 'oauth2', 'basic', 'service_account', 'token']).toContain(integration.authType);

        expect(integration.syncFrequencies).toBeDefined();
        expect(Array.isArray(integration.syncFrequencies)).toBe(true);
        expect(integration.syncFrequencies.length).toBeGreaterThan(0);

        expect(integration.configFields).toBeDefined();
        expect(Array.isArray(integration.configFields)).toBe(true);

        expect(integration.evidenceTypes).toBeDefined();
        expect(Array.isArray(integration.evidenceTypes)).toBe(true);
      });
    });

    it('config fields have valid structure', () => {
      Object.values(INTEGRATION_TYPES).forEach((integration: IntegrationType) => {
        integration.configFields.forEach((field: ConfigField) => {
          expect(field.key).toBeDefined();
          expect(typeof field.key).toBe('string');
          
          expect(field.label).toBeDefined();
          expect(typeof field.label).toBe('string');
          
          expect(field.type).toBeDefined();
          expect(['text', 'password', 'textarea', 'select', 'url', 'checkbox']).toContain(field.type);
          
          expect(typeof field.required).toBe('boolean');
          
          // If type is select, it should have options
          if (field.type === 'select') {
            expect(field.options).toBeDefined();
            expect(Array.isArray(field.options)).toBe(true);
            if (field.options && field.options.length > 0) {
              field.options.forEach((option: any) => {
                // Options can be either strings or objects with value/label
                if (typeof option === 'string') {
                  expect(option.length).toBeGreaterThan(0);
                } else {
                  expect(option.value).toBeDefined();
                  expect(option.label).toBeDefined();
                }
              });
            }
          }
        });
      });
    });

    it('evidence types have valid structure', () => {
      Object.values(INTEGRATION_TYPES).forEach((integration: IntegrationType) => {
        integration.evidenceTypes.forEach((evidence: EvidenceType) => {
          expect(evidence.key).toBeDefined();
          expect(typeof evidence.key).toBe('string');
          
          expect(evidence.label).toBeDefined();
          expect(typeof evidence.label).toBe('string');
          
          expect(evidence.description).toBeDefined();
          expect(typeof evidence.description).toBe('string');
          
          expect(typeof evidence.defaultEnabled).toBe('boolean');
        });
      });
    });
  });

  describe('Cloud Infrastructure Integrations', () => {
    it('includes AWS integration', () => {
      expect(INTEGRATION_TYPES.aws).toBeDefined();
      expect(INTEGRATION_TYPES.aws.category).toBe('Cloud Infrastructure');
      expect(INTEGRATION_TYPES.aws.evidenceTypes.length).toBeGreaterThan(0);
    });

    it('AWS has expected config fields', () => {
      const awsFields = INTEGRATION_TYPES.aws.configFields.map((f: ConfigField) => f.key);
      expect(awsFields).toContain('accessKeyId');
      expect(awsFields).toContain('secretAccessKey');
      expect(awsFields).toContain('region');
    });

    it('includes GCP integration', () => {
      expect(INTEGRATION_TYPES.gcp).toBeDefined();
      expect(INTEGRATION_TYPES.gcp.category).toBe('Cloud Infrastructure');
    });

    it('includes Azure integration', () => {
      expect(INTEGRATION_TYPES.azure).toBeDefined();
      expect(INTEGRATION_TYPES.azure.category).toBe('Cloud Infrastructure');
    });
  });

  describe('Identity Provider Integrations', () => {
    it('includes Okta integration', () => {
      expect(INTEGRATION_TYPES.okta).toBeDefined();
      expect(INTEGRATION_TYPES.okta.category).toBe('Identity Providers');
    });

    it('includes Azure AD integration', () => {
      expect(INTEGRATION_TYPES.azure_ad).toBeDefined();
      expect(INTEGRATION_TYPES.azure_ad.category).toBe('Identity Providers');
    });
  });

  describe('HR Tools Integrations', () => {
    it('includes BambooHR integration', () => {
      expect(INTEGRATION_TYPES.bamboohr).toBeDefined();
      expect(INTEGRATION_TYPES.bamboohr.category).toBe('HR Tools');
    });

    it('includes Workday integration', () => {
      expect(INTEGRATION_TYPES.workday).toBeDefined();
      expect(INTEGRATION_TYPES.workday.category).toBe('HR Tools');
    });
  });

  describe('Background Check Integrations', () => {
    it('includes Certn integration', () => {
      expect(INTEGRATION_TYPES.certn).toBeDefined();
      expect(INTEGRATION_TYPES.certn.category).toBe('Background Check');
    });

    it('includes Checkr integration', () => {
      expect(INTEGRATION_TYPES.checkr).toBeDefined();
      expect(INTEGRATION_TYPES.checkr.category).toBe('Background Check');
    });
  });

  describe('Developer Tools Integrations', () => {
    it('includes GitHub integration', () => {
      expect(INTEGRATION_TYPES.github).toBeDefined();
      expect(INTEGRATION_TYPES.github.category).toBe('Developer Tools');
    });

    it('includes GitLab integration', () => {
      expect(INTEGRATION_TYPES.gitlab).toBeDefined();
      expect(INTEGRATION_TYPES.gitlab.category).toBe('Developer Tools');
    });

    it('includes Bitbucket integration', () => {
      expect(INTEGRATION_TYPES.bitbucket).toBeDefined();
      expect(INTEGRATION_TYPES.bitbucket.category).toBe('Developer Tools');
    });
  });

  describe('Security Awareness Integrations', () => {
    it('includes KnowBe4 integration', () => {
      expect(INTEGRATION_TYPES.knowbe4).toBeDefined();
      expect(INTEGRATION_TYPES.knowbe4.category).toBe('Security Awareness');
    });
  });

  describe('Integration Categories', () => {
    it('has multiple categories', () => {
      const categories = new Set(
        Object.values(INTEGRATION_TYPES).map((i: IntegrationType) => i.category)
      );
      expect(categories.size).toBeGreaterThan(5);
    });

    it('includes expected categories', () => {
      const categories = new Set(
        Object.values(INTEGRATION_TYPES).map((i: IntegrationType) => i.category)
      );
      
      expect(categories.has('Cloud Infrastructure')).toBe(true);
      expect(categories.has('Identity Providers')).toBe(true);
      expect(categories.has('HR Tools')).toBe(true);
      expect(categories.has('Developer Tools')).toBe(true);
    });
  });

  describe('API Documentation Links', () => {
    it('most integrations have API docs', () => {
      const integrationsWithDocs = Object.values(INTEGRATION_TYPES).filter(
        (i: IntegrationType) => i.apiDocs
      );
      
      // At least 50% should have docs
      expect(integrationsWithDocs.length).toBeGreaterThan(
        Object.keys(INTEGRATION_TYPES).length * 0.5
      );
    });

    it('API doc URLs are valid URLs when present', () => {
      Object.values(INTEGRATION_TYPES).forEach((integration: IntegrationType) => {
        if (integration.apiDocs) {
          expect(() => new URL(integration.apiDocs as string)).not.toThrow();
        }
      });
    });
  });

  describe('Sync Frequencies', () => {
    it('all integrations have valid sync frequencies', () => {
      const validFrequencies = ['realtime', 'hourly', 'daily', 'weekly', 'monthly', 'manual'];
      
      Object.values(INTEGRATION_TYPES).forEach((integration: IntegrationType) => {
        integration.syncFrequencies.forEach((freq) => {
          expect(validFrequencies).toContain(freq);
        });
      });
    });
  });
});

