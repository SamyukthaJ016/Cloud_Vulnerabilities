# Risk Heatmap

The Risk Heatmap provides a visual representation of your organization's risk landscape, displaying risks by their likelihood and impact on a color-coded grid.

## Overview

The heatmap helps you:
- Visualize risk distribution at a glance
- Identify concentration of high-severity risks
- Compare inherent vs. residual risk
- Track risk movement over time

## Reading the Heatmap

### Grid Layout

```
                    IMPACT
           Neg.  Minor  Mod.  Major  Severe
         ┌──────┬──────┬──────┬──────┬──────┐
Certain  │ ●3   │ ●5   │ ●2   │ ●1   │ ●2   │
         ├──────┼──────┼──────┼──────┼──────┤
Likely   │ ●1   │ ●4   │ ●8   │ ●3   │ ●1   │
         ├──────┼──────┼──────┼──────┼──────┤
Possible │ ●2   │ ●6   │ ●12  │ ●5   │ ●2   │
L        ├──────┼──────┼──────┼──────┼──────┤
I        │ ●4   │ ●8   │ ●7   │ ●2   │      │
K        ├──────┼──────┼──────┼──────┼──────┤
E        │ ●5   │ ●3   │ ●2   │      │      │
L        └──────┴──────┴──────┴──────┴──────┘
I
H
O
O
D
```

### Color Coding

| Color | Risk Level | Action |
|-------|------------|--------|
| 🟢 Green | Very Low / Low | Monitor periodically |
| 🟡 Yellow | Medium | Regular review |
| 🟠 Orange | High | Priority attention |
| 🔴 Red | Very High / Critical | Immediate action |

### Numbers
The number in each cell shows how many risks fall into that category.

## Interacting with the Heatmap

### Hover
Hover over any cell to see:
- Risk count
- List of risk titles
- Average age of risks

### Click
Click a cell to:
- View detailed risk list
- Navigate to filtered Risk Register
- See risk details

### Risk Tooltips
Hovering over risk indicators shows:
- Risk title and ID
- Current status
- Owner
- Quick actions

## Heatmap Views

### Inherent Risk View
Shows risks as assessed without controls:
- Useful for understanding raw risk exposure
- Helps prioritize control implementation

### Residual Risk View
Shows risks after controls applied:
- Reflects current risk posture
- Basis for treatment decisions

### Toggle Between Views
Use the **View** toggle to switch:
- Inherent | Residual

## Filters

### Category Filter
Show risks by category:
- All categories
- Operational only
- Security only
- Compliance only
- etc.

### Status Filter
Show risks by status:
- All statuses
- Open risks only
- In treatment
- Accepted

### Time Period
Show risks from:
- Current snapshot
- Point-in-time historical view

### Workspace Filter
If multi-workspace enabled:
- All workspaces
- Specific workspace

## Movement Tracking

### Risk Movement Arrows
Arrows show how risks have moved:
- ↗ Risk increased (bad)
- ↘ Risk decreased (good)
- → Risk unchanged

### Time Comparison
Compare heatmap between two dates:
1. Click **Compare**
2. Select start and end dates
3. See risk movement visualization

## Analytics

### Risk Concentration
Identifies cells with many risks:
- Highlights clusters
- Suggests focus areas

### Quadrant Analysis
Divides heatmap into quadrants:
- **High Impact, High Likelihood**: Critical focus
- **High Impact, Low Likelihood**: Monitor closely
- **Low Impact, High Likelihood**: Efficiency improvements
- **Low Impact, Low Likelihood**: Accept and monitor

## Export Options

### Image Export
1. Click **Export**
2. Select **Image**
3. Choose format (PNG, SVG)
4. Download or copy

### Data Export
1. Click **Export**
2. Select **Data**
3. Choose format (CSV, Excel)
4. Download risk data by cell

### Report Export
1. Click **Export**
2. Select **Report**
3. Get formatted PDF with analysis

## Presentation Mode

For meetings and presentations:
1. Click **Present**
2. Full-screen heatmap
3. Click cells to drill down
4. Press Escape to exit

## Customization

### Color Thresholds
Adjust risk level colors:
1. Go to **Settings → Risk Configuration**
2. Modify risk matrix thresholds
3. Colors update accordingly

### Label Display
Show/hide on heatmap:
- Risk counts
- Risk indicators
- Movement arrows

## Best Practices

### Regular Review
- Review heatmap weekly
- Track movement trends
- Discuss in risk meetings

### Focus Areas
- Prioritize red cells
- Address orange cells next
- Don't ignore yellow accumulation

### Action Items
- Document actions for each high cell
- Track progress at meetings
- Celebrate improvements

## Related Topics

- [Risk Dashboard](dashboard.md)
- [Risk Assessment](assessment.md)
- [Risk Treatment](treatment.md)
- [Risk Scenarios](scenarios.md)

