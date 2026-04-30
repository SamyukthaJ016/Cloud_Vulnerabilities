/**
 * MCP Server Configuration
 * 
 * Defines available MCP servers and their configuration.
 * Servers are spawned as child processes and communicate via stdio.
 */

export interface MCPServerConfig {
  id: string;
  name: string;
  description: string;
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  autoStart?: boolean;
  healthCheckEndpoint?: string;
  timeout?: number;
  maxRetries?: number;
  capabilities: {
    tools?: boolean;
    prompts?: boolean;
    resources?: boolean;
  };
}

export const MCP_SERVERS: MCPServerConfig[] = [
  {
    id: 'grc-evidence',
    name: 'GRC Evidence Collector',
    description: 'Automated evidence collection from cloud providers and enterprise tools',
    command: 'node',
    args: ['dist/index.js'],
    cwd: 'mcp-servers/grc-evidence',
    autoStart: true,
    timeout: 30000,
    maxRetries: 3,
    capabilities: {
      tools: true,
      resources: false,
      prompts: false,
    },
  },
  {
    id: 'grc-compliance',
    name: 'GRC Compliance Checker',
    description: 'Framework compliance validation and control testing',
    command: 'node',
    args: ['dist/index.js'],
    cwd: 'mcp-servers/grc-compliance',
    autoStart: true,
    timeout: 60000,
    maxRetries: 3,
    capabilities: {
      tools: true,
      resources: false,
      prompts: false,
    },
  },
  {
    id: 'grc-ai-assistant',
    name: 'GRC AI Assistant',
    description: 'AI-powered GRC analysis and recommendations',
    command: 'node',
    args: ['dist/index.js'],
    cwd: 'mcp-servers/grc-ai-assistant',
    autoStart: false, // Requires API keys
    timeout: 120000,
    maxRetries: 2,
    capabilities: {
      tools: true,
      prompts: true,
      resources: false,
    },
  },
];

export function getServerConfig(serverId: string): MCPServerConfig | undefined {
  return MCP_SERVERS.find(s => s.id === serverId);
}

export function getAutoStartServers(): MCPServerConfig[] {
  return MCP_SERVERS.filter(s => s.autoStart);
}

/**
 * Tool definitions for each MCP server
 * These define what actions can be performed via each server
 */
export const MCP_TOOLS = {
  'grc-evidence': [
    {
      name: 'collect_aws_evidence',
      description: 'Collect evidence from AWS (CloudTrail, Config, IAM)',
      inputSchema: {
        type: 'object',
        properties: {
          evidenceType: { type: 'string', enum: ['cloudtrail', 'config', 'iam', 'all'] },
          region: { type: 'string' },
          startDate: { type: 'string', format: 'date-time' },
          endDate: { type: 'string', format: 'date-time' },
        },
        required: ['evidenceType'],
      },
    },
    {
      name: 'collect_azure_evidence',
      description: 'Collect evidence from Azure (Activity Log, Policies)',
      inputSchema: {
        type: 'object',
        properties: {
          evidenceType: { type: 'string', enum: ['activity', 'policies', 'security', 'all'] },
          subscriptionId: { type: 'string' },
        },
        required: ['evidenceType'],
      },
    },
    {
      name: 'collect_github_evidence',
      description: 'Collect evidence from GitHub (branch protection, security settings)',
      inputSchema: {
        type: 'object',
        properties: {
          organization: { type: 'string' },
          repository: { type: 'string' },
        },
        required: ['organization'],
      },
    },
    {
      name: 'collect_okta_evidence',
      description: 'Collect evidence from Okta (users, policies, logs)',
      inputSchema: {
        type: 'object',
        properties: {
          evidenceType: { type: 'string', enum: ['users', 'policies', 'logs', 'all'] },
        },
        required: ['evidenceType'],
      },
    },
    {
      name: 'capture_screenshot',
      description: 'Capture a screenshot of a URL as evidence',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string' },
          fullPage: { type: 'boolean' },
        },
        required: ['url'],
      },
    },
  ],
  'grc-compliance': [
    {
      name: 'check_soc2_compliance',
      description: 'Run SOC 2 compliance checks',
      inputSchema: {
        type: 'object',
        properties: {
          trustServiceCategory: { type: 'string', enum: ['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy'] },
          controlIds: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    {
      name: 'check_iso27001_compliance',
      description: 'Run ISO 27001 compliance checks',
      inputSchema: {
        type: 'object',
        properties: {
          controlDomains: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    {
      name: 'check_hipaa_compliance',
      description: 'Run HIPAA compliance checks',
      inputSchema: {
        type: 'object',
        properties: {
          safeguardType: { type: 'string', enum: ['administrative', 'physical', 'technical'] },
        },
      },
    },
    {
      name: 'validate_policy',
      description: 'Validate a policy document against framework requirements',
      inputSchema: {
        type: 'object',
        properties: {
          policyId: { type: 'string' },
          framework: { type: 'string', enum: ['soc2', 'iso27001', 'hipaa', 'gdpr'] },
        },
        required: ['policyId', 'framework'],
      },
    },
    {
      name: 'generate_compliance_report',
      description: 'Generate a compliance report',
      inputSchema: {
        type: 'object',
        properties: {
          framework: { type: 'string' },
          format: { type: 'string', enum: ['pdf', 'html', 'json'] },
        },
        required: ['framework'],
      },
    },
  ],
  'grc-ai-assistant': [
    {
      name: 'analyze_risk',
      description: 'AI analysis of a risk scenario',
      inputSchema: {
        type: 'object',
        properties: {
          riskDescription: { type: 'string' },
          context: { type: 'string' },
        },
        required: ['riskDescription'],
      },
    },
    {
      name: 'suggest_controls',
      description: 'AI-powered control suggestions',
      inputSchema: {
        type: 'object',
        properties: {
          riskId: { type: 'string' },
          framework: { type: 'string' },
        },
        required: ['riskId'],
      },
    },
    {
      name: 'draft_policy',
      description: 'AI-assisted policy drafting',
      inputSchema: {
        type: 'object',
        properties: {
          policyType: { type: 'string' },
          requirements: { type: 'array', items: { type: 'string' } },
        },
        required: ['policyType'],
      },
    },
    {
      name: 'explain_finding',
      description: 'Explain an audit finding in plain language',
      inputSchema: {
        type: 'object',
        properties: {
          findingId: { type: 'string' },
          audience: { type: 'string', enum: ['technical', 'executive', 'auditor'] },
        },
        required: ['findingId'],
      },
    },
    {
      name: 'prioritize_remediations',
      description: 'AI-prioritized remediation recommendations',
      inputSchema: {
        type: 'object',
        properties: {
          findingIds: { type: 'array', items: { type: 'string' } },
          constraints: { type: 'object' },
        },
        required: ['findingIds'],
      },
    },
  ],
};
