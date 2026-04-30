export const GRC_PROMPTS = {
    'risk-assessment': {
        description: 'Guide for conducting a comprehensive risk assessment',
        arguments: [
            { name: 'scope', description: 'Scope of the risk assessment', required: true },
            { name: 'methodology', description: 'Risk assessment methodology (qualitative, quantitative, hybrid)', required: false },
        ],
        template: `You are a risk assessment expert. Help conduct a comprehensive risk assessment.

# Risk Assessment Guide

## Scope
{scope}

## Methodology
{methodology}

## Assessment Steps

### 1. Asset Identification
- Identify all assets within scope
- Classify assets by criticality
- Document asset owners

### 2. Threat Identification
- Identify potential threat sources
- Consider internal and external threats
- Review historical incident data

### 3. Vulnerability Assessment
- Identify vulnerabilities in systems and processes
- Assess control effectiveness
- Document gaps

### 4. Risk Analysis
- Calculate likelihood and impact
- Determine inherent and residual risk
- Prioritize risks

### 5. Risk Treatment
- Identify treatment options (mitigate, accept, transfer, avoid)
- Recommend controls
- Document treatment plans

### 6. Documentation
- Record all findings
- Create risk register entries
- Document assumptions and limitations

Please provide details about the scope and I will help guide you through each step.`,
    },
    'policy-review': {
        description: 'Guidelines for reviewing and improving security policies',
        arguments: [
            { name: 'policy_type', description: 'Type of policy being reviewed', required: true },
            { name: 'framework', description: 'Compliance framework alignment', required: false },
        ],
        template: `You are a policy review expert. Help review and improve the security policy.

# Policy Review Checklist

## Policy Type
{policy_type}

## Framework Alignment
{framework}

## Review Criteria

### Structure
- [ ] Clear purpose statement
- [ ] Defined scope
- [ ] Roles and responsibilities
- [ ] Policy statements
- [ ] Compliance requirements
- [ ] Enforcement clause
- [ ] Review schedule

### Content Quality
- [ ] Clear, unambiguous language
- [ ] Actionable requirements
- [ ] Appropriate detail level
- [ ] Current and relevant

### Compliance Alignment
- [ ] Maps to framework requirements
- [ ] Addresses regulatory obligations
- [ ] Consistent with other policies

### Effectiveness
- [ ] Achieves stated objectives
- [ ] Measurable outcomes
- [ ] Practical implementation

Provide the policy content and I will conduct a detailed review.`,
    },
    'incident-response': {
        description: 'Incident response guidance and playbook',
        arguments: [
            { name: 'incident_type', description: 'Type of security incident', required: true },
            { name: 'severity', description: 'Incident severity level', required: false },
        ],
        template: `You are an incident response expert. Help guide the response to the security incident.

# Incident Response Playbook

## Incident Type
{incident_type}

## Severity Level
{severity}

## Response Phases

### 1. Detection & Analysis
- Verify the incident
- Determine scope and impact
- Document initial findings
- Assign severity level

### 2. Containment
- Implement immediate containment measures
- Preserve evidence
- Prevent further damage
- Communicate with stakeholders

### 3. Eradication
- Identify root cause
- Remove threat from environment
- Patch vulnerabilities
- Verify removal

### 4. Recovery
- Restore systems from clean backups
- Verify system integrity
- Monitor for reoccurrence
- Resume normal operations

### 5. Post-Incident
- Conduct post-mortem
- Document lessons learned
- Update procedures
- Brief stakeholders

## Communication Templates
- Internal notification
- Customer notification (if required)
- Regulatory notification (if required)

Describe the incident and I will provide specific guidance.`,
    },
    'compliance-audit-prep': {
        description: 'Preparation guide for compliance audits',
        arguments: [
            { name: 'framework', description: 'Compliance framework for the audit', required: true },
            { name: 'audit_type', description: 'Type of audit (internal, external, certification)', required: false },
        ],
        template: `You are a compliance audit expert. Help prepare for the upcoming audit.

# Audit Preparation Guide

## Framework
{framework}

## Audit Type
{audit_type}

## Preparation Checklist

### Documentation Review
- [ ] Policies and procedures current
- [ ] Evidence repository organized
- [ ] Control documentation complete
- [ ] Previous audit findings addressed

### Evidence Collection
- [ ] System configurations documented
- [ ] Access reviews completed
- [ ] Training records available
- [ ] Incident logs prepared
- [ ] Change management records ready

### Control Testing
- [ ] Key controls tested internally
- [ ] Gaps identified and documented
- [ ] Remediation plans in place

### Stakeholder Preparation
- [ ] Process owners briefed
- [ ] Interview schedules confirmed
- [ ] SMEs identified for each control area

### Logistics
- [ ] Audit room prepared
- [ ] System access provisioned for auditors
- [ ] Point of contact assigned

## Common Audit Focus Areas
1. Access Management
2. Change Management
3. Incident Response
4. Data Protection
5. Vendor Management

Specify the framework and I will provide detailed preparation guidance.`,
    },
    'control-design': {
        description: 'Guide for designing effective security controls',
        arguments: [
            { name: 'risk', description: 'Risk to be addressed by the control', required: true },
            { name: 'control_type', description: 'Type of control (preventive, detective, corrective)', required: false },
        ],
        template: `You are a security control design expert. Help design an effective control.

# Control Design Guide

## Risk Being Addressed
{risk}

## Control Type
{control_type}

## Design Considerations

### Control Objectives
- What specific risk is being mitigated?
- What is the desired outcome?
- How will effectiveness be measured?

### Control Attributes
- Type: Preventive / Detective / Corrective
- Implementation: Manual / Automated / Hybrid
- Frequency: Continuous / Periodic / Event-driven

### Design Principles
- Defense in depth
- Least privilege
- Segregation of duties
- Fail-safe defaults

### Implementation Requirements
- Technical requirements
- Process requirements
- Resource requirements
- Training requirements

### Testing Approach
- Test cases
- Expected results
- Evidence to collect

### Documentation
- Control description
- Operating procedures
- Evidence requirements
- Review schedule

Describe the risk and I will help design an appropriate control.`,
    },
    'vendor-assessment': {
        description: 'Third-party vendor security assessment guide',
        arguments: [
            { name: 'vendor_name', description: 'Name of the vendor', required: true },
            { name: 'service_type', description: 'Type of service provided', required: false },
            { name: 'data_classification', description: 'Classification of data accessed', required: false },
        ],
        template: `You are a third-party risk management expert. Help assess the vendor.

# Vendor Security Assessment

## Vendor
{vendor_name}

## Service Type
{service_type}

## Data Classification
{data_classification}

## Assessment Framework

### 1. Due Diligence Review
- Company background and financial stability
- Security certifications (SOC 2, ISO 27001)
- Regulatory compliance status
- References and reputation

### 2. Security Questionnaire Areas
- Information Security Program
- Access Management
- Data Protection
- Network Security
- Incident Response
- Business Continuity
- Physical Security
- Personnel Security

### 3. Technical Assessment
- Architecture review
- Vulnerability assessment results
- Penetration test results
- Security monitoring capabilities

### 4. Contractual Requirements
- Data protection clauses
- Security requirements
- Audit rights
- Incident notification
- Termination provisions

### 5. Risk Classification
- Inherent risk level
- Control effectiveness
- Residual risk
- Approval recommendation

Provide vendor details and I will guide the assessment process.`,
    },
};
export function getPromptMessages(promptName, args) {
    const prompt = GRC_PROMPTS[promptName];
    if (!prompt) {
        throw new Error(`Unknown prompt: ${promptName}`);
    }
    // Replace placeholders in template
    let content = prompt.template;
    for (const [key, value] of Object.entries(args)) {
        content = content.replace(new RegExp(`\\{${key}\\}`, 'g'), value || 'Not specified');
    }
    // Replace any remaining placeholders with defaults
    for (const arg of prompt.arguments) {
        content = content.replace(new RegExp(`\\{${arg.name}\\}`, 'g'), 'Not specified');
    }
    return [
        {
            role: 'user',
            content,
        },
    ];
}
//# sourceMappingURL=grc-prompts.js.map