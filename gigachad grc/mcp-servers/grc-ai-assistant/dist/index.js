#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ListPromptsRequestSchema, GetPromptRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { analyzeRisk } from './tools/risk-analyzer.js';
import { suggestControls } from './tools/control-suggester.js';
import { draftPolicy } from './tools/policy-drafter.js';
import { mapRequirements } from './tools/requirement-mapper.js';
import { explainFinding } from './tools/finding-explainer.js';
import { prioritizeRemediation } from './tools/remediation-prioritizer.js';
import { analyzeComplianceGap } from './tools/gap-analyzer.js';
import { assessVendorRisk } from './tools/vendor-risk-assessor.js';
import { GRC_PROMPTS, getPromptMessages } from './prompts/grc-prompts.js';
// Server instance
const server = new Server({
    name: 'grc-ai-assistant-server',
    version: '1.0.0',
}, {
    capabilities: {
        tools: {},
        prompts: {},
    },
});
// Define available tools
const tools = [
    {
        name: 'analyze_risk',
        description: 'Perform deep AI-powered risk analysis with scoring suggestions and mitigation strategies',
        inputSchema: {
            type: 'object',
            properties: {
                riskDescription: {
                    type: 'string',
                    description: 'Description of the risk to analyze',
                },
                context: {
                    type: 'object',
                    properties: {
                        industry: { type: 'string' },
                        organizationSize: { type: 'string' },
                        frameworks: { type: 'array', items: { type: 'string' } },
                        existingControls: { type: 'array', items: { type: 'string' } },
                    },
                    description: 'Context about the organization',
                },
                includeQuantitative: {
                    type: 'boolean',
                    description: 'Include quantitative risk analysis (ALE, SLE)',
                },
            },
            required: ['riskDescription'],
        },
    },
    {
        name: 'suggest_controls',
        description: 'Recommend appropriate controls for identified risks',
        inputSchema: {
            type: 'object',
            properties: {
                risk: {
                    type: 'object',
                    properties: {
                        title: { type: 'string' },
                        description: { type: 'string' },
                        category: { type: 'string' },
                        currentLikelihood: { type: 'string' },
                        currentImpact: { type: 'string' },
                    },
                    required: ['title', 'description'],
                },
                frameworks: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Target compliance frameworks',
                },
                maxSuggestions: {
                    type: 'number',
                    description: 'Maximum number of control suggestions',
                },
            },
            required: ['risk'],
        },
    },
    {
        name: 'draft_policy',
        description: 'Generate policy document drafts based on requirements',
        inputSchema: {
            type: 'object',
            properties: {
                policyType: {
                    type: 'string',
                    enum: [
                        'information_security',
                        'access_control',
                        'data_classification',
                        'incident_response',
                        'acceptable_use',
                        'password',
                        'remote_work',
                        'vendor_management',
                        'data_retention',
                        'privacy',
                    ],
                    description: 'Type of policy to draft',
                },
                frameworks: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Compliance frameworks to align with',
                },
                organizationContext: {
                    type: 'object',
                    properties: {
                        name: { type: 'string' },
                        industry: { type: 'string' },
                        size: { type: 'string' },
                        specificRequirements: { type: 'array', items: { type: 'string' } },
                    },
                },
                format: {
                    type: 'string',
                    enum: ['markdown', 'html', 'plain'],
                    description: 'Output format for the policy',
                },
            },
            required: ['policyType'],
        },
    },
    {
        name: 'map_requirements',
        description: 'Auto-map controls to framework requirements',
        inputSchema: {
            type: 'object',
            properties: {
                control: {
                    type: 'object',
                    properties: {
                        id: { type: 'string' },
                        title: { type: 'string' },
                        description: { type: 'string' },
                        category: { type: 'string' },
                    },
                    required: ['title', 'description'],
                },
                targetFrameworks: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Frameworks to map to',
                },
                confidenceThreshold: {
                    type: 'number',
                    description: 'Minimum confidence score for mappings (0-1)',
                },
            },
            required: ['control', 'targetFrameworks'],
        },
    },
    {
        name: 'explain_finding',
        description: 'Explain audit findings in plain language with remediation steps',
        inputSchema: {
            type: 'object',
            properties: {
                finding: {
                    type: 'object',
                    properties: {
                        title: { type: 'string' },
                        description: { type: 'string' },
                        severity: { type: 'string' },
                        framework: { type: 'string' },
                        controlReference: { type: 'string' },
                    },
                    required: ['title', 'description'],
                },
                audience: {
                    type: 'string',
                    enum: ['technical', 'executive', 'auditor', 'general'],
                    description: 'Target audience for the explanation',
                },
                includeRemediation: {
                    type: 'boolean',
                    description: 'Include step-by-step remediation guidance',
                },
            },
            required: ['finding'],
        },
    },
    {
        name: 'prioritize_remediation',
        description: 'AI-prioritized remediation list based on risk and effort',
        inputSchema: {
            type: 'object',
            properties: {
                findings: {
                    type: 'array',
                    items: {
                        type: 'object',
                        properties: {
                            id: { type: 'string' },
                            title: { type: 'string' },
                            severity: { type: 'string' },
                            category: { type: 'string' },
                            estimatedEffort: { type: 'string' },
                        },
                    },
                    description: 'List of findings to prioritize',
                },
                constraints: {
                    type: 'object',
                    properties: {
                        budget: { type: 'number' },
                        timeframeWeeks: { type: 'number' },
                        teamSize: { type: 'number' },
                    },
                    description: 'Resource constraints',
                },
                prioritizationStrategy: {
                    type: 'string',
                    enum: ['risk_based', 'compliance_deadline', 'quick_wins', 'balanced'],
                    description: 'Strategy for prioritization',
                },
            },
            required: ['findings'],
        },
    },
    {
        name: 'analyze_compliance_gap',
        description: 'Analyze gaps between current state and target compliance framework',
        inputSchema: {
            type: 'object',
            properties: {
                currentControls: {
                    type: 'array',
                    items: {
                        type: 'object',
                        properties: {
                            id: { type: 'string' },
                            title: { type: 'string' },
                            status: { type: 'string' },
                        },
                    },
                    description: 'List of current controls',
                },
                targetFramework: {
                    type: 'string',
                    description: 'Target compliance framework',
                },
                includeRoadmap: {
                    type: 'boolean',
                    description: 'Include implementation roadmap',
                },
            },
            required: ['currentControls', 'targetFramework'],
        },
    },
    {
        name: 'assess_vendor_risk',
        description: 'AI-powered vendor risk assessment',
        inputSchema: {
            type: 'object',
            properties: {
                vendor: {
                    type: 'object',
                    properties: {
                        name: { type: 'string' },
                        category: { type: 'string' },
                        services: { type: 'array', items: { type: 'string' } },
                        dataAccess: { type: 'array', items: { type: 'string' } },
                    },
                    required: ['name'],
                },
                assessmentData: {
                    type: 'object',
                    properties: {
                        securityQuestionnaire: { type: 'object' },
                        certifications: { type: 'array', items: { type: 'string' } },
                        previousIncidents: { type: 'array', items: { type: 'string' } },
                    },
                },
                riskAppetite: {
                    type: 'string',
                    enum: ['low', 'medium', 'high'],
                    description: 'Organization risk appetite',
                },
            },
            required: ['vendor'],
        },
    },
];
// Define available prompts
const prompts = Object.entries(GRC_PROMPTS).map(([name, prompt]) => ({
    name,
    description: prompt.description,
    arguments: prompt.arguments,
}));
// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
});
// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
        let result;
        // Cast args to unknown first to allow conversion to specific param types
        const toolArgs = args;
        switch (name) {
            case 'analyze_risk':
                result = await analyzeRisk(toolArgs);
                break;
            case 'suggest_controls':
                result = await suggestControls(toolArgs);
                break;
            case 'draft_policy':
                result = await draftPolicy(toolArgs);
                break;
            case 'map_requirements':
                result = await mapRequirements(toolArgs);
                break;
            case 'explain_finding':
                result = await explainFinding(toolArgs);
                break;
            case 'prioritize_remediation':
                result = await prioritizeRemediation(toolArgs);
                break;
            case 'analyze_compliance_gap':
                result = await analyzeComplianceGap(toolArgs);
                break;
            case 'assess_vendor_risk':
                result = await assessVendorRisk(toolArgs);
                break;
            default:
                throw new Error(`Unknown tool: ${name}`);
        }
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                },
            ],
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({ error: errorMessage }),
                },
            ],
            isError: true,
        };
    }
});
// Handle list prompts request
server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return { prompts };
});
// Handle get prompt request
server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const prompt = GRC_PROMPTS[name];
    if (!prompt) {
        throw new Error(`Unknown prompt: ${name}`);
    }
    const messages = getPromptMessages(name, args || {});
    return {
        description: prompt.description,
        messages,
    };
});
// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('GRC AI Assistant MCP Server running on stdio');
}
main().catch(console.error);
//# sourceMappingURL=index.js.map