# Test Procedures

Test procedures provide a structured approach to control testing during audits. GigaChad GRC supports multiple test types with configurable sampling and comprehensive documentation.

## Overview

Control testing validates that controls are designed properly and operating effectively. Test procedures document:
- What is being tested
- How testing was performed
- Sample selection methodology
- Results and conclusions

## Accessing Test Procedures

1. Navigate to **Audit → Test Procedures** for all procedures
2. Or from a specific audit, go to the **Test Procedures** tab

## Test Types

### Inquiry
- Interviews with control owners
- Walkthroughs of processes
- Discussion of control design
- Documentation of responses

### Observation
- Watching controls in action
- Real-time process observation
- Environmental controls inspection
- Physical security assessments

### Inspection
- Document review
- System configuration analysis
- Evidence examination
- Policy and procedure review

### Reperformance
- Re-executing control steps
- Independent calculation verification
- System testing with test data
- Parallel processing validation

## Creating a Test Procedure

1. Click **Create Test Procedure** button
2. Fill in procedure details:

### Basic Information
- **Procedure Number**: Auto-generated or custom (e.g., TP-001)
- **Title**: Descriptive name
- **Control**: Link to the control being tested
- **Test Type**: Select inquiry, observation, inspection, or reperformance

### Sampling Configuration
- **Sample Size**: Number of items to test
- **Sample Selection**: Random, systematic, judgmental, or haphazard
- **Population**: Description of the full population
- **Period**: Audit period for testing

### Testing Details
- **Description**: Detailed procedure steps
- **Expected Result**: What a passing test looks like
- **Documentation Requirements**: What evidence to retain

3. Click **Save** to create the procedure

## Sample Selection Methods

### Random Selection
- Items selected using random number generator
- Most objective method
- Good for large populations
- System can generate random samples

### Systematic Selection
- Select every nth item
- Starting point is random
- Ensures coverage across population
- Good for sequential records

### Judgmental Selection
- Tester uses professional judgment
- Focus on higher-risk items
- May include outliers or exceptions
- Requires documentation of rationale

### Haphazard Selection
- Selection without specific method
- Not truly random
- Acceptable for some tests
- Quick for small populations

## Executing Tests

1. Open the test procedure
2. Click **Begin Testing**
3. Document your work:
   - Record actual results
   - Note any exceptions
   - Attach evidence
4. Select conclusion:
   - **Effective**: Control operated as designed
   - **Partially Effective**: Minor deviations noted
   - **Ineffective**: Significant failures identified
   - **N/A**: Control not applicable or not testable
5. Add conclusion rationale
6. Click **Submit for Review**

## Recording Results

### Actual Result
Document what you found during testing:
```
Tested 25 access request tickets from Q3 2024.

Results:
- 24/25 had proper manager approval
- 24/25 matched approved access levels
- 1 exception: Ticket #12345 missing approval
```

### Exceptions
For each exception, document:
- Description of the issue
- Impact assessment
- Root cause (if determined)
- Management response

### Conclusion Rationale
Explain your conclusion:
```
Based on 25 sample items, 24 (96%) met all control criteria.
One exception identified is considered isolated.
Control is operating effectively with minor exception.
```

## Review Process

Test procedures follow a two-stage review:

### Tester Sign-off
1. Complete all testing
2. Document results and conclusions
3. Attach supporting evidence
4. Submit for review

### Reviewer Sign-off
1. Review testing methodology
2. Validate sample selection
3. Verify conclusions are supported
4. Approve or request changes

## Common Test Procedures

### Access Management Testing
```
Procedure: Test user access provisioning controls
Test Type: Inspection
Sample Size: 25 new hires from audit period
Expected Result: Each access request has:
  - Manager approval email or ticket
  - Access matches job requirements
  - Provisioning within SLA
```

### Change Management Testing
```
Procedure: Test change approval process
Test Type: Inspection
Sample Size: 25 production changes
Expected Result: Each change has:
  - Documented change request
  - CAB approval (for high-risk)
  - Testing evidence
  - Rollback plan
```

### Password Policy Testing
```
Procedure: Verify password complexity enforcement
Test Type: Reperformance
Sample Size: 10 test scenarios
Expected Result: System rejects passwords that:
  - Are less than 12 characters
  - Lack uppercase letters
  - Lack numbers or special characters
```

## Best Practices

1. **Document Everything**: Detailed documentation supports conclusions
2. **Appropriate Sample Sizes**: Use professional standards (e.g., AICPA guidance)
3. **Timely Testing**: Test throughout the period, not just at year-end
4. **Clear Conclusions**: Link results directly to control objectives
5. **Consistent Methodology**: Use same approach across similar controls

## Integration with Findings

When exceptions are identified:
1. Document in test procedure results
2. Create a finding if significant
3. Link test procedure to finding
4. Finding triggers remediation workflow

## API Reference

See the [API Documentation](/docs/API.md#test-procedures) for programmatic access.

