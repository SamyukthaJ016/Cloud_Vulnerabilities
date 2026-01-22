# Test Deep Scan Functionality

## Quick Test via Browser Console

Open your browser's developer console (F12) and run this command before clicking "Start Scan":

```javascript
// Check if deep scan checkbox is checked
console.log('Deep Scan Enabled:', document.getElementById('deepScan').checked);

// Monitor the scan request
const originalFetch = window.fetch;
window.fetch = function(...args) {
    if (args[0].includes('/scan/multi-cloud')) {
        console.log('🔍 Scan Request URL:', args[0]);
        if (args[1] && args[1].body) {
            const body = JSON.parse(args[1].body);
            console.log('📦 Scan Request Body:', body);
            console.log('✅ Deep Scan in Request:', body.deep_scan);
        }
    }
    return originalFetch.apply(this, args);
};
```

Then click "Start Security Scan" and check the console output.

---

## Expected Output

You should see:
```
Deep Scan Enabled: true
📦 Scan Request Body: {providers: ["gcp"], account_ids: {}, deep_scan: true, user_id: "anonymous"}
✅ Deep Scan in Request: true
```

---

## If Deep Scan is FALSE

If you see `deep_scan: false`, then the checkbox is unchecked. To fix:

1. **Check the checkbox manually** before scanning
2. **Or** verify line 904 in `frontend/index.html` has `checked` attribute

---

## Backend Verification

Check the backend logs for this line:
```
[GCP] Starting full scan (deep=True)...
[GCP] Running OWASP web application vulnerability scans...
```

If you see `deep=False`, the parameter isn't being passed correctly.

---

## Manual API Test

Test directly with curl to bypass the UI:

```bash
curl -X POST http://localhost:8000/scan/multi-cloud \
  -H "Content-Type: application/json" \
  -d '{
    "providers": ["gcp"],
    "account_ids": {"gcp": "gcp-goat-05582cdf552deada"},
    "deep_scan": true,
    "offensive_scan": false
  }'
```

This should return **17+ vulnerabilities** instead of 11.

---

## Check Backend Logs

Look for these log messages:

```
✅ GOOD (Deep Scan Enabled):
[GCP] Starting full scan (deep=True)...
[GCP] Found 2 HTTP endpoints to scan
[GCP] Running XSS scan on blogapp
[GCP] Running SSRF tests...
[GCP] Web application scan found 6 vulnerabilities

❌ BAD (Deep Scan Disabled):
[GCP] Starting full scan (deep=False)...
[GCP] Scan complete: 22 resources, 11 findings
```

---

## Most Likely Issue

Based on your results showing exactly 11 vulnerabilities (all infrastructure), I suspect:

1. **Deep scan checkbox is unchecked** when you run the scan
2. **Or** the scan is timing out during web app testing
3. **Or** Cloud Functions don't have HTTP endpoints configured

---

## Next Steps

1. Run the browser console test above
2. Check backend logs for `deep=True` or `deep=False`
3. If deep=True but still no web vulns, check if Cloud Functions have HTTP URLs
4. Share the console output and I'll help debug further
