"""
GCPGoat-Specific Vulnerability Scanner
Enhanced detection for GCPGoat's known vulnerabilities
"""

import logging
import aiohttp
import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, quote

logger = logging.getLogger("gcpgoat_scanner")


class GCPGoatScanner:
    """Enhanced scanner specifically designed to detect GCPGoat vulnerabilities"""
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=10)
    
    async def scan_endpoint(self, url: str, resource_name: str, resource_type: str) -> List[Dict[str, Any]]:
        """
        Comprehensive scan of a single endpoint for all GCPGoat vulnerabilities.
        Now includes deeper path discovery and automated crawling.
        """
        findings = []
        logger.info(f"[GCPGoat-Scanner] Starting DEEP scan on {resource_type} '{resource_name}' ({url})")
        
        # Initial discovery: Try to find links and parameters from the root response
        discovered_params = set([
            "url", "uri", "path", "file", "id", "user_id", "q", "search", "name",
            "query", "s", "search_term", "next", "target", "dest", "cmd", "exec", 
            "username", "password", "email", "token", "content", "title", "comment"
        ])
        discovered_paths = set([
            "", "/", "/blog", "/api/blog", "/api/users", "/get_file", 
            "/reset", "/forgot", "/admin", "/login", "/register", 
            "/search", "/profile", "/dashboard", "/api/v1/user"
        ])
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Simple regex to find parameters in common patterns like ?param= or input name="param"
                        discovered_params.update(re.findall(r'[?&]([a-zA-Z0-9_-]+)=', text))
                        discovered_params.update(re.findall(r'name=["\']([a-zA-Z0-9_-]+)["\']', text))
                        # Find potential API paths
                        discovered_paths.update(re.findall(r'["\'](/[a-zA-Z0-9/_.-]+)["\']', text))
        except Exception as e:
            logger.debug(f"[GCPGoat-Scanner] Initial discovery failed for {url}: {e}")

        # Run all scans in parallel
        # We pass discovered items to improve coverage
        tasks = [
            self.test_xss(url, resource_name, resource_type, list(discovered_params), list(discovered_paths)),
            self.test_ssrf(url, resource_name, resource_type, list(discovered_params)),
            self.test_idor(url, resource_name, resource_type, list(discovered_paths)),
            self.test_sensitive_data(url, resource_name, resource_type),
            self.test_password_reset(url, resource_name, resource_type, list(discovered_paths)),
            self.test_lfi(url, resource_name, resource_type, list(discovered_params)),
            self.test_discovery(url, resource_name, resource_type)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all findings
        scan_count = 0
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
                scan_count += len(result)
            elif isinstance(result, Exception):
                logger.error(f"[GCPGoat-Scanner] Scan module error on {url}: {result}")
        
        logger.info(f"[GCPGoat-Scanner] DEEP scan complete for {url}. Found {scan_count} unique issues.")
        return findings
    
    async def test_xss(self, url: str, resource_name: str, resource_type: str, extra_params: List[str] = None, extra_paths: List[str] = None) -> List[Dict]:
        """
        Advanced XSS testing with broad parameter and path coverage
        """
        findings = []
        logger.debug(f"[GCPGoat-Scanner] Testing XSS on {url}")
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                paths = list(set(["", "/blog", "/post", "/comment", "/api/blog", "/api/users"] + (extra_paths or [])))
                param_names = list(set(["title", "content", "comment", "name", "message", "search", "q", "query", "id", "user"] + (extra_params or [])))
                
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "';alert('XSS');//"
                ]
                
                async def test_single_xss(path, param, payload):
                    test_base_url = url.rstrip('/') + path if path.startswith('/') else url.rstrip('/') + '/' + path
                    try:
                        # Test GET
                        test_url = f"{test_base_url}?{param}={quote(payload)}"
                        async with session.get(test_url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=3)) as response:
                            if response.status == 200:
                                text = await response.text()
                                if payload in text:
                                    return {
                                        "severity": "HIGH",
                                        "issue": "Reflected Cross-Site Scripting (XSS)",
                                        "description": f"XSS detected via parameter '{param}' at {path}.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "parameter": param,
                                        "recommendation": "Encode all output and implement a strong CSP.",
                                        "detection_tool": "gcpgoat_xss_scanner"
                                    }
                    except:
                        pass
                    return None

                # OPTIMIZED: Run XSS tests in groups to avoid overwhelming the server
                tasks = []
                for path in paths:
                    for param in param_names:
                        for payload in xss_payloads:
                            tasks.append(test_single_xss(path, param, payload))
                
                # Run in batches of 20 to be respectful but fast
                for i in range(0, len(tasks), 20):
                    batch = tasks[i:i+20]
                    batch_results = await asyncio.gather(*batch, return_exceptions=True)
                    for res in batch_results:
                        if isinstance(res, dict): findings.append(res)
                    if findings: break # Stop if we found XSS to save time
        except Exception as e:
            logger.error(f"XSS test failed: {e}")
        return findings
    
    async def test_ssrf(self, url: str, resource_name: str, resource_type: str, extra_params: List[str] = None) -> List[Dict]:
        """
        Enhanced SSRF testing targeting GCP Metadata and internal services
        """
        findings = []
        logger.debug(f"[GCPGoat-Scanner] Testing SSRF on {url}")
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                param_names = list(set(["url", "uri", "host", "dest", "redirect", "u", "path", "proxy", "fetch", "link"] + (extra_params or [])))
                
                ssrf_payloads = [
                    "http://metadata.google.internal/computeMetadata/v1/instance/id",
                    "http://169.254.169.254/computeMetadata/v1/instance/id",
                    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                    "http://www.google.com" # Generic SSRF check
                ]
                
                async def test_single_ssrf(param, payload):
                    test_url = f"{url}?{param}={quote(payload)}"
                    try:
                        async with session.get(test_url, allow_redirects=False, headers={"Metadata-Flavor": "Google"}, timeout=aiohttp.ClientTimeout(total=3)) as response:
                            text = await response.text()
                            if response.status == 200:
                                if any(x in text for x in ["computeMetadata", "project-id", "access_token"]) or ("google" in text.lower() and "http://www.google.com" == payload):
                                    return {
                                        "severity": "CRITICAL",
                                        "issue": "Server-Side Request Forgery (SSRF)",
                                        "description": f"SSRF detected in {resource_name}. Parameter '{param}' allows arbitrary URL fetching.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "parameter": param,
                                        "recommendation": "Apply strict allowlists for outbound requests.",
                                        "detection_tool": "gcpgoat_ssrf_scanner"
                                    }
                    except:
                        pass
                    return None

                # OPTIMIZED: Parallel SSRF testing
                tasks = []
                for param in param_names:
                    for payload in ssrf_payloads:
                        tasks.append(test_single_ssrf(param, payload))
                
                ssrf_results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in ssrf_results:
                    if isinstance(res, dict): 
                        findings.append(res)
                        break # Stop on first critical SSRF
        except Exception as e:
            logger.error(f"SSRF test failed: {e}")
        return findings

    async def test_idor(self, url: str, resource_name: str, resource_type: str, extra_paths: List[str] = None) -> List[Dict]:
        """
        IDOR testing with expanded path discovery
        """
        findings = []
        logger.debug(f"[GCPGoat-Scanner] Testing IDOR on {url}")
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                base_paths = ["/api/blog/1", "/api/users/1", "/api/posts/1", "/api/comments/1", "/user/1"]
                api_paths = list(set(base_paths + (extra_paths or [])))
                
                for path in api_paths:
                    if not re.search(r'/\d+$', path): continue # Only test sequential IDs
                    
                    test_url_base = url.rstrip('/') + path
                    try:
                        async with session.get(test_url_base) as resp1:
                            if resp1.status != 200: continue
                            body1 = await resp1.text()
                            
                        # Test IDs 2 through 5
                        for i in range(2, 6):
                            test_url = re.sub(r'/\d+$', f'/{i}', test_url_base)
                            async with session.get(test_url) as resp2:
                                if resp2.status == 200:
                                    body2 = await resp2.text()
                                    if body1 != body2 and len(body2) > 20:
                                        findings.append({
                                            "severity": "HIGH",
                                            "issue": "Insecure Direct Object Reference (IDOR)",
                                            "description": f"IDOR detected at {path}. Accessing ID {i} returns different authorized data.",
                                            "resource_name": resource_name,
                                            "url": test_url,
                                            "recommendation": "Use non-sequential IDs (UUIDs) and verify object ownership on every request.",
                                            "detection_tool": "gcpgoat_idor_scanner"
                                        })
                                        return findings
                    except:
                        continue
        except Exception as e:
            logger.error(f"IDOR test failed: {e}")
        return findings

    async def test_lfi(self, url: str, resource_name: str, resource_type: str, extra_params: List[str] = None) -> List[Dict]:
        """
        Test for Local File Inclusion (LFI)
        """
        findings = []
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                params = list(set(["file", "path", "doc", "view", "include", "page", "template"] + (extra_params or [])))
                payloads = ["/etc/passwd", "../../../etc/passwd", "main.py", "app.py", ".env"]
                
                for param in params:
                    for payload in payloads:
                        try:
                            test_url = f"{url}?{param}={quote(payload)}"
                            async with session.get(test_url) as response:
                                if response.status == 200:
                                    text = await response.text()
                                    if any(x in text for x in ["root:x:0:0:", "DATABASE_URL", "PORT="]):
                                        findings.append({
                                            "severity": "CRITICAL",
                                            "issue": "Local File Inclusion (LFI)",
                                            "description": f"LFI detected in {resource_name} via parameter '{param}'. Resource at '{payload}' was exposed.",
                                            "resource_name": resource_name,
                                            "url": test_url,
                                            "payload": payload,
                                            "recommendation": "Restrict file access to a specific directory and validate input against an allowlist.",
                                            "detection_tool": "gcpgoat_lfi_scanner"
                                        })
                                        return findings
                        except: continue
        except: pass
        return findings

    async def test_discovery(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """
        Scan for sensitive hidden files and directories
        """
        findings = []
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                sensitive_files = [".env", ".git/config", "config.json", "settings.py", "web.config", "Dockerfile"]
                for f in sensitive_files:
                    test_url = url.rstrip('/') + '/' + f
                    try:
                        async with session.get(test_url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                if len(text) > 10 and resp.headers.get('Content-Type') != 'text/html':
                                    findings.append({
                                        "severity": "HIGH",
                                        "issue": "Sensitive File Exposure",
                                        "description": f"Sensitive file '{f}' is publicly accessible at {test_url}.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "recommendation": "Block access to sensitive files using .htaccess, web.config, or application logic.",
                                        "detection_tool": "gcpgoat_discovery_scanner"
                                    })
                    except: continue
        except: pass
        return findings
    
    async def test_sensitive_data(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """
        Test for sensitive data exposure
        """
        findings = []
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as response:
                    text = await response.text()
                    headers = response.headers
                    
                    # Enhanced secret patterns for GCPGoat
                    secret_patterns = {
                        "GCP Service Account Key": r'"type":\s*"service_account"',
                        "GCP Private Key": r'"private_key":\s*"-----BEGIN PRIVATE KEY-----',
                        "GCP API Key": r'AIza[0-9A-Za-z\\-_]{35}',
                        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
                        "Database Password": r'(?i)(password|passwd|pwd|db_pass)["\']\s*:\s*["\'][^"\']{3,}["\']',
                        "API Token": r'"(api[_-]?token|access[_-]?token|auth[_-]?token)"\s*:\s*"[^"]{10,}"',
                        "JWT Token": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
                        "Connection String": r'(mongodb|mysql|postgres|postgresql)://[^\\s"\']+',
                        "Email Addresses": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        "Internal IP": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
                    }
                    
                    for secret_type, pattern in secret_patterns.items():
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        if matches:
                            # Filter out false positives for emails and IPs
                            if secret_type in ["Email Addresses", "Internal IP"] and len(matches) < 3:
                                continue
                            
                            severity = "CRITICAL" if secret_type in ["GCP Service Account Key", "GCP Private Key", "AWS Access Key", "Database Password"] else "HIGH"
                            
                            findings.append({
                                "severity": severity,
                                "issue": f"Sensitive Data Exposure: {secret_type}",
                                "description": f"Sensitive data ({secret_type}) exposed in {resource_type} '{resource_name}' response. Found {len(matches)} instance(s). This could lead to credential theft and unauthorized access.",
                                "resource_name": resource_name,
                                "url": url,
                                "evidence_count": len(matches),
                                "recommendation": f"Remove all sensitive data from API responses in {resource_name}. Never expose credentials, private keys, or tokens in HTTP responses. Use environment variables and Google Secret Manager for sensitive data.",
                                "detection_tool": "gcpgoat_secret_scanner",
                                "owasp": "A02:2021 – Cryptographic Failures"
                            })
                    
                    # Check for verbose error messages
                    error_patterns = [
                        (r'Traceback \(most recent call last\)', "Python Stack Trace"),
                        (r'at com\.google\.cloud', "Java Stack Trace"),
                        (r'Error:\s*ENOENT', "Node.js Error"),
                        (r'SQLException', "SQL Error"),
                        (r'Internal Server Error.*<pre>', "Detailed Error Page")
                    ]
                    
                    for pattern, error_type in error_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            findings.append({
                                "severity": "MEDIUM",
                                "issue": f"Verbose Error Messages: {error_type}",
                                "description": f"Detailed error messages or stack traces exposed in {resource_type} '{resource_name}'. This reveals internal application structure and can aid attackers.",
                                "resource_name": resource_name,
                                "url": url,
                                "recommendation": f"Implement custom error pages in {resource_name}. Log detailed errors server-side but return generic error messages to users.",
                                "detection_tool": "gcpgoat_error_scanner",
                                "owasp": "A05:2021 – Security Misconfiguration"
                            })
                            break
                    
                    # Check security headers
                    missing_headers = []
                    if 'Content-Security-Policy' not in headers:
                        missing_headers.append('Content-Security-Policy')
                    if 'X-Content-Type-Options' not in headers:
                        missing_headers.append('X-Content-Type-Options')
                    if 'X-Frame-Options' not in headers:
                        missing_headers.append('X-Frame-Options')
                    if 'Strict-Transport-Security' not in headers:
                        missing_headers.append('Strict-Transport-Security')
                    
                    if missing_headers:
                        findings.append({
                            "severity": "LOW",
                            "issue": "Missing Security Headers",
                            "description": f"{resource_type} '{resource_name}' is missing {len(missing_headers)} security headers: {', '.join(missing_headers)}",
                            "resource_name": resource_name,
                            "url": url,
                            "missing_headers": missing_headers,
                            "recommendation": f"Add security headers to {resource_name}: Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security: max-age=31536000",
                            "detection_tool": "gcpgoat_header_scanner",
                            "owasp": "A05:2021 – Security Misconfiguration"
                        })
        
        except Exception as e:
            logger.error(f"Sensitive data scanning failed for {resource_name}: {e}")
        
        return findings
    
    async def test_password_reset(self, url: str, resource_name: str, resource_type: str, extra_paths: List[str] = None) -> List[Dict]:
        """
        Expanded password reset vulnerability testing
        """
        findings = []
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                reset_endpoints = list(set(['/reset', '/forgot', '/api/reset', '/password/reset'] + (extra_paths or [])))
                for endpoint in reset_endpoints:
                    if "reset" not in endpoint.lower() and "forgot" not in endpoint.lower(): continue
                    test_url = urljoin(url, endpoint)
                    try:
                        async with session.get(test_url) as resp:
                            if resp.status < 500: # Exists
                                # Check for token in URL
                                if "token=" in str(resp.url):
                                    findings.append({
                                        "severity": "HIGH",
                                        "issue": "Insecure Password Reset: Token in URL",
                                        "description": f"Reset token exposed in URL at {test_url}.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "recommendation": "Send tokens in the response body or via POST only.",
                                        "detection_tool": "gcpgoat_password_scanner"
                                    })
                                # Rate limit check
                                success_count = 0
                                for _ in range(4):
                                    async with session.post(test_url, json={"email": "test@example.com"}) as r:
                                        if r.status < 400: success_count += 1
                                    await asyncio.sleep(0.05)
                                if success_count >= 3:
                                    findings.append({
                                        "severity": "MEDIUM",
                                        "issue": "Password Reset: No Rate Limiting",
                                        "description": f"No rate limiting on reset endpoint at {test_url}.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "recommendation": "Implement IP-based and account-based rate limiting.",
                                        "detection_tool": "gcpgoat_password_scanner"
                                    })
                                    return findings
                    except: continue
        except: pass
        return findings
