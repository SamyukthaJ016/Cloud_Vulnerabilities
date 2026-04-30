# Risk Treatment

Risk treatment is the process of deciding how to address identified risks and implementing appropriate response strategies. This guide covers treatment options, workflows, and best practices.

## Treatment Options

### Mitigate
Reduce the likelihood or impact through controls:
- Implement new security controls
- Enhance existing controls
- Add process safeguards

**When to use**: Risk level is unacceptable and can be reduced cost-effectively.

### Accept
Acknowledge and accept the risk without action:
- Document acceptance decision
- Monitor for changes
- May require executive approval

**When to use**: Risk is within appetite, or mitigation cost exceeds benefit.

### Transfer
Shift risk to a third party:
- Insurance policies
- Contractual transfer to vendors
- Outsourcing

**When to use**: Risk can be better managed by another party.

### Avoid
Eliminate the risk entirely:
- Stop the risky activity
- Change business process
- Exit the market/service

**When to use**: Risk is unacceptable and cannot be adequately mitigated.

## Treatment Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Risk Analyzed  │───▶│    Treatment    │───▶│   In Treatment  │
│                 │    │    Decision     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                       │
                              │                       ▼
                              │               ┌─────────────────┐
                              │               │   Treatment     │
                              │               │   Complete      │
                              │               └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │ Executive       │
                       │ Approval        │ (if high risk)
                       └─────────────────┘
```

## Starting Treatment

### From Risk Detail
1. Open an analyzed risk
2. Click **Begin Treatment**
3. Treatment form opens

### From Risk Queue
1. Go to **Risk Management → My Queue**
2. Find risks pending treatment
3. Click **Treat** to begin

## Treatment Form

### Treatment Decision
Select primary treatment strategy:
- Mitigate
- Accept
- Transfer
- Avoid

### Justification
Document why this treatment was chosen:
- Cost-benefit analysis
- Business considerations
- Available alternatives

### Treatment Plan

#### For Mitigation
- Describe mitigation actions
- Link controls to implement
- Set target completion date
- Assign owner

#### For Acceptance
- Document acceptance rationale
- Set acceptance expiration date
- Identify approvers

#### For Transfer
- Identify transfer mechanism (insurance, contract)
- Document transfer arrangements
- Residual risk after transfer

#### For Avoidance
- Describe how risk will be avoided
- Business process changes
- Timeline for changes

## Executive Approval

High and Critical risks typically require executive approval:

### Approval Routing
1. Treatment owner submits for approval
2. System routes to appropriate executive
3. Executive reviews and approves/rejects
4. If rejected, returns with feedback

### Approval Criteria
Based on risk configuration:
- Very High/Critical: Executive approval required
- High: Management approval may be required
- Medium and below: Risk owner can approve

## Tracking Progress

### Mitigation Progress
For mitigation treatments:
1. Go to risk detail → **Treatment** tab
2. Click **Update Progress**
3. Enter completion percentage
4. Add status notes
5. Upload supporting evidence

### Status Updates
Record periodic updates:
- Progress percentage
- Milestones completed
- Issues encountered
- Timeline adjustments

### Evidence
Attach evidence of treatment completion:
- Control implementation proof
- Configuration changes
- Policy updates
- Test results

## Treatment Completion

### Marking Complete
1. Open the risk in treatment
2. Go to **Treatment** tab
3. Click **Complete Treatment**
4. Provide completion notes
5. Upload final evidence
6. Submit for review

### Verification
After completion:
1. GRC team verifies treatment
2. Residual risk reassessed
3. Risk status updated
4. Monitoring scheduled

## Monitoring

After treatment, risks enter monitoring:

### Active Monitoring
- Periodic check-ins
- Key risk indicators
- Control effectiveness testing

### Trigger Events
Reopen treatment if:
- New vulnerabilities identified
- Control failures occur
- Business changes impact risk

## Reporting

### Treatment Status Report
Shows:
- Treatments in progress
- Overdue treatments
- Completion rates
- Average treatment time

### Treatment Effectiveness
Analyzes:
- Risk reduction achieved
- Cost of treatments
- Control effectiveness
- Residual risk levels

## Best Practices

### Treatment Selection
- Consider all options before deciding
- Document rationale thoroughly
- Get stakeholder input

### Planning
- Set realistic timelines
- Break into milestones
- Assign clear ownership

### Execution
- Update progress regularly
- Document challenges
- Adjust plans as needed

### Documentation
- Keep evidence current
- Record all decisions
- Maintain audit trail

## Related Topics

- [Risk Assessment](assessment.md)
- [Risk Dashboard](dashboard.md)
- [Creating Risks](creating-risks.md)

