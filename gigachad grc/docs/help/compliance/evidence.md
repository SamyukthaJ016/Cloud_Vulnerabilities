# Evidence Collection

Evidence artifacts demonstrate that your security controls are implemented and operating effectively. This guide covers uploading, organizing, and managing compliance evidence.

## Overview

The Evidence Library provides:
- Centralized storage for all compliance artifacts
- Version control and history
- Control and framework linking
- Automated retention policies
- Search and filtering

## Evidence Types

| Type | Description | Examples |
|------|-------------|----------|
| **Screenshot** | Visual proof of configuration | System settings, dashboards |
| **Document** | Written documentation | Policies, procedures, reports |
| **Export** | System-generated data | Configuration exports, logs |
| **Report** | Formal reports | Audit reports, assessments |
| **Certificate** | Certifications | SSL certificates, compliance certs |
| **Log** | System logs | Access logs, audit trails |

## Uploading Evidence

### Single File Upload
1. Navigate to **Data → Evidence**
2. Click **Upload Evidence**
3. Select or drag-and-drop your file
4. Fill in metadata:
   - **Title**: Descriptive name
   - **Description**: What this evidence proves
   - **Type**: Category of evidence
   - **Category**: Security domain
   - **Collection Date**: When collected
   - **Expiration Date**: When to refresh (optional)
5. Click **Upload**

### Bulk Upload
1. Click **Upload Evidence**
2. Drag multiple files at once
3. Review and edit metadata for each
4. Click **Upload All**

### Supported File Types
- Documents: PDF, DOC, DOCX, XLS, XLSX
- Images: PNG, JPG, GIF
- Archives: ZIP (will be extracted)
- Text: TXT, CSV, JSON, XML
- Maximum file size: 50MB per file

## Organizing Evidence

### Categories
Evidence is organized by security domain:
- Access Control
- Asset Management
- Business Continuity
- Compliance
- Data Protection
- Human Resources
- Incident Response
- Network Security
- Physical Security
- Risk Management
- Vendor Management

### Tags
Add custom tags for additional organization:
1. Open evidence detail
2. Click **Add Tag**
3. Type tag name
4. Press Enter

### Folders (Optional)
Create logical folders for large evidence libraries:
1. Click **New Folder**
2. Name the folder
3. Drag evidence into folders

## Linking to Controls

Evidence should be linked to the controls it supports:

### From Evidence
1. Open evidence detail
2. Go to **Linked Controls** tab
3. Click **Link Control**
4. Select controls
5. Add relationship notes

### From Controls
1. Open a control
2. Go to **Evidence** tab
3. Click **Link Evidence**
4. Select evidence items

## Evidence Lifecycle

### Collection
1. Identify what evidence is needed
2. Capture the artifact (screenshot, export, etc.)
3. Upload to the platform
4. Add descriptive metadata

### Review
1. Verify evidence is accurate and complete
2. Check that it supports the intended control
3. Approve or request re-collection

### Refresh
Evidence expires and needs periodic refresh:
1. Set expiration dates when uploading
2. Dashboard shows expiring evidence
3. Notifications remind owners
4. Upload new version before expiration

### Retention
Configure retention policies:
- **Default**: Keep all versions
- **Custom**: Delete old versions after X days
- **Compliance**: Meet framework retention requirements

## Searching Evidence

### Quick Search
Type in the search bar to find evidence by:
- Title
- Description
- File name
- Tags

### Advanced Filters
- **Type**: Document, Screenshot, etc.
- **Category**: Security domain
- **Status**: Active, Expired, Pending Review
- **Date Range**: Collection or upload date
- **Linked Controls**: Evidence for specific controls

## Evidence Detail Page

Click any evidence to see:

### Information Tab
- File preview (images, PDFs)
- Metadata and description
- Upload and collection dates

### Linked Controls Tab
- Controls this evidence supports
- Framework requirements covered

### Version History
- Previous versions of the evidence
- Download old versions
- Compare changes

### Activity
- Upload history
- Link/unlink events
- Comments

## Storage Backends

Evidence can be stored in:
- **Local Storage**: Default, files on server
- **RustFS/S3**: Object storage for scalability
- **Azure Blob**: Microsoft cloud storage

Contact your administrator to configure storage.

## Best Practices

### Evidence Quality
- ✅ Include timestamps in screenshots
- ✅ Use descriptive file names
- ✅ Add context in the description
- ✅ Collect from authoritative sources
- ❌ Don't upload personally sensitive data
- ❌ Avoid blurry or cropped screenshots

### Organization
- Create a consistent naming convention
- Use categories and tags consistently
- Link evidence to all relevant controls
- Set realistic expiration dates

### Security
- Evidence may contain sensitive information
- Access is controlled by permissions
- Consider redacting confidential data
- Audit logs track all access

## Automation

### Automated Collection
Integrate with systems to auto-collect evidence:
- Use **Integrations** to connect systems
- Schedule periodic evidence pulls
- Auto-link to relevant controls

### Evidence Collectors
Configure evidence collectors for:
- Cloud platforms (AWS, Azure, GCP)
- Identity providers
- SIEM systems
- Endpoint management

See [Integrations](../integrations/connecting-integrations.md) for setup.

## Related Topics

- [Controls Management](controls.md)
- [Framework Management](managing-frameworks.md)
- [Integrations](../integrations/connecting-integrations.md)

