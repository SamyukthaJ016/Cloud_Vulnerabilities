import { createContext, useContext, useMemo, ReactNode, useState, useCallback } from 'react';

/**
 * Module Configuration System
 * 
 * This context provides configuration for which platform modules are enabled.
 * Modules can be toggled via environment variables or organization settings.
 * 
 * Usage:
 * - Set VITE_ENABLE_*_MODULE=true/false in .env
 * - Use useModules() hook to check if a module is enabled
 * - Use <ModuleGuard module="risk"> to conditionally render components
 */

// ============================================
// Module Definitions
// ============================================

export type ModuleId = 
  | 'compliance'    // Controls, Frameworks, Evidence, Calendar
  | 'data'          // Policies, Assets, Integrations
  | 'risk'          // Risk Dashboard, Register, Heatmap, Scenarios
  | 'tprm'          // Vendors, Assessments, Contracts, Questionnaires
  | 'bcdr'          // BC/DR Dashboard, Processes, Plans, Tests, Runbooks
  | 'audit'         // Audits, Findings, Requests, Audit Log
  | 'trust'         // Trust Center, Knowledge Base
  | 'people'        // Employees, Compliance Dashboard, Training
  | 'ai'            // AI Features, MCP Servers
  | 'tools'         // Scheduled Reports, Custom Dashboards
  | 'config-as-code'; // Configuration as Code

export interface ModuleDefinition {
  id: ModuleId;
  name: string;
  description: string;
  envVar: string;
  defaultEnabled: boolean;
  routes: string[];      // Route prefixes this module covers
  navSections: string[]; // Navigation section names to show/hide
  dependencies?: ModuleId[]; // Modules this depends on
}

export const MODULE_DEFINITIONS: Record<ModuleId, ModuleDefinition> = {
  compliance: {
    id: 'compliance',
    name: 'Compliance',
    description: 'Controls, Frameworks, Evidence collection, and Compliance Calendar',
    envVar: 'VITE_ENABLE_COMPLIANCE_MODULE',
    defaultEnabled: true,
    routes: ['/controls', '/frameworks', '/framework-library', '/evidence', '/calendar'],
    navSections: ['Compliance'],
  },
  data: {
    id: 'data',
    name: 'Data Management',
    description: 'Policies, Assets, and third-party Integrations',
    envVar: 'VITE_ENABLE_DATA_MODULE',
    defaultEnabled: true,
    routes: ['/policies', '/assets', '/integrations'],
    navSections: ['Data'],
  },
  risk: {
    id: 'risk',
    name: 'Risk Management',
    description: 'Risk Dashboard, Risk Register, Heatmap, and Scenario Analysis',
    envVar: 'VITE_ENABLE_RISK_MODULE',
    defaultEnabled: true,
    routes: ['/risks', '/risk-dashboard', '/risk-queue', '/risk-heatmap', '/risk-scenarios', '/risk-reports'],
    navSections: ['Risk Management'],
  },
  tprm: {
    id: 'tprm',
    name: 'Third Party Risk',
    description: 'Vendor management, Assessments, Contracts, and Security Questionnaires',
    envVar: 'VITE_ENABLE_TPRM_MODULE',
    defaultEnabled: true,
    routes: ['/vendors', '/assessments', '/contracts', '/questionnaires'],
    navSections: ['Third Party Risk'],
  },
  bcdr: {
    id: 'bcdr',
    name: 'BC/DR',
    description: 'Business Continuity, Disaster Recovery, and Resilience Planning',
    envVar: 'VITE_ENABLE_BCDR_MODULE',
    defaultEnabled: true,
    routes: ['/bcdr'],
    navSections: ['BC/DR'],
  },
  audit: {
    id: 'audit',
    name: 'Audit',
    description: 'Internal audits, Findings, Audit Requests, and Audit Log',
    envVar: 'VITE_ENABLE_AUDIT_MODULE',
    defaultEnabled: true,
    routes: ['/audits', '/audit-requests', '/audit-findings', '/audit', '/audit-templates', '/audit-workpapers', '/test-procedures', '/audit-analytics', '/audit-calendar'],
    navSections: ['Audit'],
  },
  trust: {
    id: 'trust',
    name: 'Trust Center',
    description: 'Public Trust Center, Knowledge Base, and Customer Communications',
    envVar: 'VITE_ENABLE_TRUST_MODULE',
    defaultEnabled: true,
    routes: ['/trust-center', '/knowledge-base'],
    navSections: ['Trust'],
  },
  people: {
    id: 'people',
    name: 'People & Compliance',
    description: 'Employee compliance tracking, Training, and Awareness',
    envVar: 'VITE_ENABLE_PEOPLE_MODULE',
    defaultEnabled: true,
    routes: ['/people', '/tools/awareness'],
    navSections: ['People'],
  },
  ai: {
    id: 'ai',
    name: 'AI Features',
    description: 'AI-powered risk analysis, Control suggestions, and MCP integration',
    envVar: 'VITE_ENABLE_AI_MODULE',
    defaultEnabled: false,
    routes: ['/settings/ai', '/settings/mcp'],
    navSections: [],
  },
  tools: {
    id: 'tools',
    name: 'Tools & Reports',
    description: 'Custom Dashboards, Scheduled Reports, and Reporting tools',
    envVar: 'VITE_ENABLE_TOOLS_MODULE',
    defaultEnabled: true,
    routes: ['/dashboards', '/scheduled-reports'],
    navSections: ['Tools'],
  },
  'config-as-code': {
    id: 'config-as-code',
    name: 'Configuration as Code',
    description: 'Manage GRC resources declaratively with version control (IDE + Export/Import)',
    envVar: 'VITE_ENABLE_CONFIG_AS_CODE_MODULE',
    defaultEnabled: true,
    routes: ['/settings/config-as-code'],
    navSections: ['Settings'],
  },
};

// ============================================
// Presets for common configurations
// ============================================

export interface ModulePreset {
  id: string;
  name: string;
  description: string;
  modules: ModuleId[];
}

export const MODULE_PRESETS: ModulePreset[] = [
  {
    id: 'full',
    name: 'Full Platform',
    description: 'All modules enabled - complete GRC functionality',
    modules: ['compliance', 'data', 'risk', 'tprm', 'bcdr', 'audit', 'trust', 'people', 'tools'],
  },
  {
    id: 'core',
    name: 'Core GRC',
    description: 'Essential compliance and risk management',
    modules: ['compliance', 'data', 'risk', 'audit'],
  },
  {
    id: 'compliance-only',
    name: 'Compliance Only',
    description: 'Controls, frameworks, and evidence management',
    modules: ['compliance', 'data'],
  },
  {
    id: 'risk-focused',
    name: 'Risk Focused',
    description: 'Risk management with vendor oversight',
    modules: ['compliance', 'data', 'risk', 'tprm'],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'Full platform with BC/DR and advanced features',
    modules: ['compliance', 'data', 'risk', 'tprm', 'bcdr', 'audit', 'trust', 'people', 'ai', 'tools'],
  },
];

// ============================================
// Module Configuration Context
// ============================================

interface ModuleConfig {
  enabledModules: Set<ModuleId>;
  isModuleEnabled: (moduleId: ModuleId) => boolean;
  isRouteEnabled: (path: string) => boolean;
  isNavSectionEnabled: (sectionName: string) => boolean;
  getEnabledModules: () => ModuleDefinition[];
  getDisabledModules: () => ModuleDefinition[];
  getActivePreset: () => ModulePreset | null;
  // Internal helper for org-level config
  _refreshFromOrgConfig?: (modules: string[] | null | undefined) => void;
}

const ModuleContext = createContext<ModuleConfig | null>(null);

// ============================================
// Environment Variable Reader
// ============================================

function getModuleEnabledFromEnv(moduleId: ModuleId): boolean {
  const definition = MODULE_DEFINITIONS[moduleId];
  const envValue = import.meta.env[definition.envVar];
  
  // If env var is not set, use default
  if (envValue === undefined || envValue === '') {
    return definition.defaultEnabled;
  }
  
  // Parse boolean from string
  return envValue === 'true' || envValue === '1';
}

function loadEnabledModules(): Set<ModuleId> {
  const enabled = new Set<ModuleId>();
  
  for (const moduleId of Object.keys(MODULE_DEFINITIONS) as ModuleId[]) {
    if (getModuleEnabledFromEnv(moduleId)) {
      enabled.add(moduleId);
    }
  }
  
  return enabled;
}

// ============================================
// Provider Component
// ============================================

interface ModuleProviderProps {
  children: ReactNode;
  // Optional override for testing or org-specific config
  overrideModules?: ModuleId[];
}

export function ModuleProvider({ children, overrideModules }: ModuleProviderProps) {
  const [enabledModules, setEnabledModules] = useState<Set<ModuleId>>(() =>
    overrideModules ? new Set(overrideModules) : loadEnabledModules(),
  );

  // Allow external callers (e.g. Settings) to refresh module configuration
  const refreshFromOrgConfig = useCallback((orgModules: string[] | null | undefined) => {
    if (overrideModules) {
      // When override is provided (tests), ignore org config
      return;
    }
    // If orgModules is explicitly null/undefined/empty, don't reset to env vars
    // This prevents API errors from disabling modules that were previously enabled
    // Only update if we have a valid array
    if (Array.isArray(orgModules)) {
      const normalized = new Set<ModuleId>();
      // Always include modules from org config, even if empty array
      // Empty array means no modules enabled via org settings (use env vars)
      if (orgModules.length > 0) {
        (Object.keys(MODULE_DEFINITIONS) as ModuleId[]).forEach((id) => {
          if (orgModules.includes(id)) {
            normalized.add(id);
          }
        });
        setEnabledModules(normalized);
      } else {
        // Empty array means no org-level modules - fall back to env vars
        setEnabledModules(loadEnabledModules());
      }
    }
    // If orgModules is null/undefined (not an array), keep current state - don't reset
    // This ensures modules stay enabled even if API call fails or returns invalid data
  }, [overrideModules]);

  const config = useMemo<ModuleConfig>(() => ({
    enabledModules,
    
    isModuleEnabled: (moduleId: ModuleId) => {
      return enabledModules.has(moduleId);
    },
    
    isRouteEnabled: (path: string) => {
      // Always allow dashboard, login, settings base, account, help, and core admin routes
      const alwaysAllowed = ['/dashboard', '/login', '/settings', '/account', '/help', '/docs', '/users', '/permissions'];
      if (alwaysAllowed.some(allowed => path === allowed || path.startsWith(allowed + '/'))) {
        // Special case: AI settings require ai module
        if (path.startsWith('/settings/ai') || path.startsWith('/settings/mcp')) {
          return enabledModules.has('ai');
        }
        // Special case: Config as Code requires config-as-code module
        if (path.startsWith('/settings/config-as-code')) {
          return enabledModules.has('config-as-code');
        }
        return true;
      }
      
      // Check if any enabled module covers this route
      for (const moduleId of enabledModules) {
        const definition = MODULE_DEFINITIONS[moduleId];
        if (definition.routes.some(route => path === route || path.startsWith(route + '/'))) {
          return true;
        }
      }
      
      return false;
    },
    
    isNavSectionEnabled: (sectionName: string) => {
      // Settings is always shown (items inside are filtered)
      if (sectionName === 'Settings') return true;
      
      // Check if any enabled module includes this nav section
      for (const moduleId of enabledModules) {
        const definition = MODULE_DEFINITIONS[moduleId];
        if (definition.navSections.includes(sectionName)) {
          return true;
        }
      }
      
      return false;
    },
    
    getEnabledModules: () => {
      return Array.from(enabledModules).map(id => MODULE_DEFINITIONS[id]);
    },
    
    getDisabledModules: () => {
      return (Object.keys(MODULE_DEFINITIONS) as ModuleId[])
        .filter(id => !enabledModules.has(id))
        .map(id => MODULE_DEFINITIONS[id]);
    },
    
    getActivePreset: () => {
      const enabledArray = Array.from(enabledModules).sort();
      
      for (const preset of MODULE_PRESETS) {
        const presetModules = [...preset.modules].sort();
        if (
          enabledArray.length === presetModules.length &&
          enabledArray.every((m, i) => m === presetModules[i])
        ) {
          return preset;
        }
      }
      
      return null; // Custom configuration
    },
    _refreshFromOrgConfig: refreshFromOrgConfig,
  }), [enabledModules, refreshFromOrgConfig]);

  return (
    <ModuleContext.Provider value={config}>
      {children}
    </ModuleContext.Provider>
  );
}

// ============================================
// Hook
// ============================================

export function useModules(): ModuleConfig {
  const context = useContext(ModuleContext);
  if (!context) {
    throw new Error('useModules must be used within a ModuleProvider');
  }
  return context;
}

// ============================================
// Guard Component
// ============================================

interface ModuleGuardProps {
  module: ModuleId;
  children: ReactNode;
  fallback?: ReactNode;
}

/**
 * Conditionally renders children only if the specified module is enabled.
 * Useful for hiding UI elements based on module configuration.
 */
export function ModuleGuard({ module, children, fallback = null }: ModuleGuardProps) {
  const { isModuleEnabled } = useModules();
  
  if (isModuleEnabled(module)) {
    return <>{children}</>;
  }
  
  return <>{fallback}</>;
}

// ============================================
// Route Guard Component
// ============================================

interface RouteModuleGuardProps {
  module: ModuleId;
  children: ReactNode;
}

/**
 * For use in route definitions - shows a "module disabled" page if module is off.
 * Import DisabledModulePage separately to use this.
 */
export function RouteModuleGuard({ module, children }: RouteModuleGuardProps) {
  const { isModuleEnabled } = useModules();
  
  if (isModuleEnabled(module)) {
    return <>{children}</>;
  }
  
  // Will be handled by DisabledModulePage component
  return null;
}

export default ModuleContext;

