# Risk Assessment

Risk assessment is the process of evaluating risks to determine their likelihood, impact, and overall risk level. This guide covers the assessment workflow in GigaChad GRC.

## Assessment Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Risk Identified │───▶│   Assessment    │───▶│ Risk Analyzed   │
│    (Intake)     │    │   In Progress   │    │   (Complete)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  GRC Approval   │
                       └─────────────────┘
```

## Starting an Assessment

### From Risk Register
1. Open the risk to assess
2. Click **Begin Assessment**
3. Assessment form opens

### From My Queue
1. Go to **Risk Management → My Queue**
2. Find risks assigned to you
3. Click **Assess** to begin

## Assessment Form

### Threat Description
Document the threat:
- What is the threat source?
- What vulnerability does it exploit?
- What asset(s) are affected?

### Likelihood Assessment
Evaluate how likely the risk is to occur:

| Level | Description | Criteria |
|-------|-------------|----------|
| **Rare** | Very unlikely | < 5% chance per year |
| **Unlikely** | Could occur | 5-25% chance |
| **Possible** | Might occur | 25-50% chance |
| **Likely** | Will probably occur | 50-75% chance |
| **Almost Certain** | Expected to occur | > 75% chance |

#### Rationale
Document why you selected this likelihood:
- Historical data
- Industry benchmarks
- Expert judgment
- Existing controls

### Impact Assessment
Evaluate the consequences if the risk occurs:

| Level | Description | Criteria |
|-------|-------------|----------|
| **Negligible** | Minimal impact | < $10K loss, no reputation damage |
| **Minor** | Low impact | $10-50K loss, minor disruption |
| **Moderate** | Medium impact | $50-250K loss, some reputation damage |
| **Major** | High impact | $250K-1M loss, significant damage |
| **Severe** | Critical impact | > $1M loss, critical damage |

#### Impact Categories
Consider impact across:
- **Financial**: Direct costs, fines, revenue loss
- **Operational**: Business disruption, productivity
- **Reputational**: Customer trust, brand damage
- **Regulatory**: Compliance violations, legal exposure

### Risk Score Calculation

The system calculates risk level using a risk matrix:

```
                    IMPACT
           Neg.  Minor  Mod.  Major  Severe
         ┌──────┬──────┬──────┬──────┬──────┐
Certain  │  M   │  H   │  VH  │  VH  │ CRIT │
         ├──────┼──────┼──────┼──────┼──────┤
Likely   │  L   │  M   │  H   │  VH  │  VH  │
         ├──────┼──────┼──────┼──────┼──────┤
Possible │  L   │  M   │  M   │  H   │  VH  │
L        ├──────┼──────┼──────┼──────┼──────┤
I        │  VL  │  L   │  M   │  M   │  H   │
K        ├──────┼──────┼──────┼──────┼──────┤
E        │  VL  │  VL  │  L   │  M   │  M   │
L        └──────┴──────┴──────┴──────┴──────┘
I
H
O
O
D
```

### Inherent vs. Residual Risk

**Inherent Risk**: Risk level before controls
**Residual Risk**: Risk level after controls

During assessment:
1. First, evaluate **inherent risk** (no controls)
2. Document existing controls
3. Re-evaluate **residual risk** (with controls)

### Linked Assets
Associate affected assets:
1. Click **Link Assets**
2. Select from asset inventory
3. Document how each asset is affected

### Linked Controls
Document existing controls that mitigate this risk:
1. Click **Link Controls**
2. Select relevant controls
3. Rate effectiveness (None, Partial, Full)

## Quantitative Assessment (Optional)

For more precise risk quantification:

### Likelihood Percentage
Enter specific probability: 0-100%

### Impact Value
Enter specific dollar amount

### Annual Loss Expectancy (ALE)
System calculates: `ALE = Likelihood% × Impact$`

Example:
- 20% likelihood × $500,000 impact = $100,000 ALE

## GRC Review

After assessment submission:

1. **GRC SME Reviews**
   - Validates likelihood and impact ratings
   - Checks rationale documentation
   - May request clarification

2. **Approval or Revision**
   - Approved: Moves to treatment
   - Rejected: Returns for revision with notes

## Assessment Quality

### Good Assessment
- ✅ Clear threat description
- ✅ Documented rationale
- ✅ Linked assets and controls
- ✅ Considered all impact categories
- ✅ Used available data

### Poor Assessment
- ❌ Vague descriptions
- ❌ No supporting rationale
- ❌ Missing asset links
- ❌ Gut-feel ratings
- ❌ Incomplete form

## Best Practices

### Consistency
- Use consistent criteria across assessments
- Calibrate with peers
- Reference past assessments

### Documentation
- Document all assumptions
- Cite data sources
- Note uncertainties

### Stakeholder Input
- Consult subject matter experts
- Get business owner perspective
- Consider multiple viewpoints

### Regular Re-assessment
- Reassess when circumstances change
- Annual reassessment at minimum
- Triggered by major events

## Related Topics

- [Creating Risks](creating-risks.md)
- [Risk Treatment](treatment.md)
- [Risk Heatmap](heatmap.md)
- [Risk Dashboard](dashboard.md)

