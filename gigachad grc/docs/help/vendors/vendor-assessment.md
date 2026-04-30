# Third-Party Vendor Management

Managing third-party vendor risk is critical for maintaining your security posture. GigaChad GRC helps you track, assess, and monitor all your vendors in one place.

## Why Vendor Management Matters

Your security is only as strong as your weakest vendor. Third-party breaches are responsible for:
- 60% of data breaches involve third parties
- Average cost of third-party breach: $4.7M
- Regulatory penalties for vendor-related incidents

## Vendor Lifecycle

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Intake    │───▶│  Assessment │───▶│  Onboarding │───▶│  Monitoring │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                                                          │
      │                                                          │
      ▼                                                          ▼
┌─────────────┐                                         ┌─────────────┐
│  Rejection  │                                         │  Offboarding │
└─────────────┘                                         └─────────────┘
```

## Adding a Vendor

### Step 1: Create Vendor Record

1. Navigate to **Vendors**
2. Click **Add Vendor**
3. Fill in basic information:
   - **Name**: Vendor's legal name
   - **Website**: Primary website
   - **Category**: Type of service (Cloud Provider, HR Software, etc.)
   - **Primary Contact**: Main point of contact

### Step 2: Classify the Vendor

Tier classification determines assessment rigor:

| Tier | Description | Assessment Level |
|------|-------------|-----------------|
| **Tier 1 - Critical** | Business-critical, handles sensitive data | Full assessment, annual review |
| **Tier 2 - Important** | Significant service, some data access | Standard assessment, bi-annual review |
| **Tier 3 - Standard** | Limited scope, minimal data access | Light assessment, annual review |
| **Tier 4 - Low Risk** | No data access, commodity service | Self-attestation only |

### Step 3: Define Data Handling

Document what data the vendor accesses:
- Customer data
- Employee data
- Financial data
- Intellectual property
- System credentials

## Vendor Assessments

### Assessment Types

#### Security Questionnaire
- Standard questionnaire based on SIG Lite, CAIQ, or custom
- Sent to vendor for completion
- Responses tracked in platform

#### Document Review
- Request and review security documents:
  - SOC 2 report
  - ISO 27001 certificate
  - Penetration test reports
  - Insurance certificates

#### Technical Assessment
- Security scanning (if applicable)
- Architecture review
- API security assessment

### Creating an Assessment

1. Open vendor record
2. Click **Start Assessment**
3. Select assessment template:
   - **SIG Lite**: Standard security questionnaire
   - **SOC 2 Review**: For vendors with SOC reports
   - **Custom**: Your organization's questionnaire
4. Set due date
5. Send to vendor contact

### Tracking Assessment Progress

Assessment dashboard shows:
- Questions answered vs. total
- Red flags identified
- Documents received
- Days until due date

### Reviewing Assessment Results

1. Review all responses
2. Flag concerning answers
3. Request clarifications
4. Document risk acceptances
5. Calculate risk score

## Risk Scoring

Vendor risk is calculated based on:

### Inherent Risk Factors
- Data sensitivity handled
- Service criticality
- Integration depth
- Geographic factors

### Security Posture
- Assessment responses
- Certifications held
- Incident history
- Security maturity

### Resulting Risk Score

```
Risk Score = Inherent Risk × (1 - Security Posture)
```

| Score | Risk Level | Action |
|-------|-----------|--------|
| 0-25 | Low | Standard monitoring |
| 26-50 | Medium | Enhanced monitoring |
| 51-75 | High | Risk mitigation required |
| 76-100 | Critical | Executive review required |

## Contract Management

Link contracts to vendors:

### Adding a Contract

1. Open vendor record
2. Go to **Contracts** tab
3. Click **Add Contract**
4. Fill in details:
   - Contract title
   - Start and end dates
   - Value
   - Auto-renewal status
   - Key terms

### Security Addenda

Ensure contracts include:
- Data processing agreement (DPA)
- Security requirements
- Breach notification terms
- Right to audit
- Termination/offboarding procedures

### Contract Reminders

Set up alerts for:
- Contract expiration (90, 60, 30 days)
- Auto-renewal deadlines
- Annual review dates
- Compliance certification renewals

## Continuous Monitoring

### Automated Monitoring

If vendors have integrations configured:
- Real-time security posture updates
- Automatic risk score adjustments
- Alert on critical changes

### Manual Reviews

Schedule periodic reviews:

| Tier | Review Frequency |
|------|-----------------|
| Tier 1 | Quarterly |
| Tier 2 | Semi-annually |
| Tier 3 | Annually |
| Tier 4 | Every 2 years |

### Monitoring Triggers

Immediate review required for:
- Security incident disclosure
- Significant acquisition/merger
- Service outage affecting your data
- Failed compliance audit
- Material contract changes

## Vendor Offboarding

When terminating a vendor relationship:

### Offboarding Checklist

- [ ] Data return or destruction confirmed
- [ ] Access credentials revoked
- [ ] Integration disconnected
- [ ] DNS/certificates updated
- [ ] Employee awareness updated
- [ ] Contract termination documented
- [ ] Final assessment recorded

### Data Destruction Verification

1. Request certificate of data destruction
2. Verify all backup copies deleted
3. Document in vendor record
4. Update data inventory

## Reporting

### Vendor Risk Dashboard

View aggregate metrics:
- Total vendors by tier
- Risk score distribution
- Upcoming reviews
- Open assessments
- Expiring contracts

### Compliance Reports

Generate reports for:
- Board presentations
- Audit requests
- Insurance renewals

### Export Options

- PDF executive summary
- Excel detailed inventory
- CSV for analysis

## Best Practices

### Build a Vendor Inventory
- Document all vendors, not just IT
- Include SaaS subscriptions
- Review corporate credit cards for shadow IT

### Standardize Assessment Process
- Use consistent questionnaires
- Define clear criteria
- Document all decisions

### Maintain Relationships
- Regular check-ins with key vendors
- Share security expectations
- Collaborate on improvements

### Plan for Incidents
- Define escalation procedures
- Test communication channels
- Include vendors in incident response plans

## Need Help?

- Review our [vendor assessment templates](/help/vendors/templates.md)
- Contact support@example.com
- Schedule vendor risk consulting

---

*Last updated: December 2025*

