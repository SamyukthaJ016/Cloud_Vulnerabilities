# Set Up a Custom URL for Your Trust Center

## Table of Contents

- [Summary](#summary)
- [Prerequisites](#prerequisites)
- [Step 1: Enable Your Custom Domain in GigaChad GRC](#step-1-enable-your-custom-domain-in-gigachad-grc)
- [Step 2: Update Your DNS Records](#step-2-update-your-dns-records)
  - [Cloudflare](#cloudflare)
  - [GoDaddy](#godaddy)
  - [Amazon Route 53](#amazon-route-53)
  - [Namecheap](#namecheap)
  - [Google Domains / Squarespace](#google-domains--squarespace)
- [Step 3: Verify Your Configuration](#step-3-verify-your-configuration)
- [SSL Certificate](#ssl-certificate)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Summary

Custom domain URLs allow you to use your own branded domain (like `trust.yourcompany.com` or `security.yourcompany.com`) instead of the default GigaChad GRC URL when sharing your Trust Center with prospects, customers, and partners.

**Benefits of using a custom domain:**
- **Brand consistency** - Keep visitors on your domain throughout their security review
- **Professional appearance** - Builds trust with a URL that matches your brand
- **Easy to remember** - Share a simple, memorable URL with stakeholders
- **SEO benefits** - Content lives on your domain

The setup involves two main steps:
1. Configuring your custom domain in GigaChad GRC
2. Adding a CNAME record with your DNS provider

Once completed, your Trust Center will be accessible at your custom URL with automatic SSL/TLS encryption.

---

## Prerequisites

Before setting up a custom domain, ensure you have:

- [ ] **Admin access** to your GigaChad GRC organization
- [ ] **Domain ownership** - You own or control the domain you want to use
- [ ] **DNS access** - You can modify DNS records for your domain (usually through your domain registrar or DNS provider)
- [ ] **Trust Center content** - Your Trust Center has been configured with content

> **Note:** If you don't have access to modify your DNS records, contact your IT administrator or the person who manages your domain.

---

## Step 1: Enable Your Custom Domain in GigaChad GRC

1. Log in to GigaChad GRC with an admin account
2. Navigate to **Trust** → **Trust Center Settings** in the sidebar
3. Click on the **Custom Domain** tab
4. Enter your desired custom domain in the text field:
   - Examples: `trust.yourcompany.com`, `security.yourcompany.com`
   - Do not include `https://` or trailing slashes
5. Click **Save**

![Custom Domain Settings](/docs/help/images/trust-center-custom-domain.png)

> **Tip:** We recommend using a subdomain like `trust` or `security` rather than your root domain. This is easier to configure and doesn't affect your main website.

---

## Step 2: Update Your DNS Records

After saving your custom domain in GigaChad GRC, you need to create a CNAME record with your DNS provider. This tells the internet to route traffic from your custom domain to your Trust Center.

### DNS Record Configuration

| Field | Value |
|-------|-------|
| **Type** | `CNAME` |
| **Host/Name** | Your subdomain (e.g., `trust` or `security`) |
| **Value/Points to** | `trust.gigachad-grc.com` |
| **TTL** | `300` (or "Auto") |

Below are step-by-step instructions for popular DNS providers:

---

### Cloudflare

1. Log in to your [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain
3. Click **DNS** in the sidebar
4. Click **Add Record**
5. Configure the record:
   - **Type:** CNAME
   - **Name:** `trust` (or your chosen subdomain)
   - **Target:** `trust.gigachad-grc.com`
   - **Proxy status:** DNS only (gray cloud) - **Important!**
   - **TTL:** Auto
6. Click **Save**

> ⚠️ **Important:** Set the proxy status to "DNS only" (gray cloud icon). If the orange cloud is enabled, SSL certificate provisioning may fail.

---

### GoDaddy

1. Log in to your [GoDaddy Account](https://account.godaddy.com)
2. Go to **My Products** → **Domains**
3. Click **DNS** next to your domain
4. Click **Add** in the Records section
5. Configure the record:
   - **Type:** CNAME
   - **Name:** `trust` (or your chosen subdomain)
   - **Value:** `trust.gigachad-grc.com`
   - **TTL:** 1 Hour (or lowest available)
6. Click **Save**

---

### Amazon Route 53

1. Log in to the [AWS Console](https://console.aws.amazon.com)
2. Navigate to **Route 53** → **Hosted zones**
3. Click on your domain
4. Click **Create record**
5. Configure the record:
   - **Record name:** `trust` (or your chosen subdomain)
   - **Record type:** CNAME
   - **Value:** `trust.gigachad-grc.com`
   - **TTL:** 300
6. Click **Create records**

---

### Namecheap

1. Log in to your [Namecheap Account](https://www.namecheap.com)
2. Go to **Domain List** → click **Manage** next to your domain
3. Click **Advanced DNS**
4. Click **Add New Record**
5. Configure the record:
   - **Type:** CNAME Record
   - **Host:** `trust` (or your chosen subdomain)
   - **Value:** `trust.gigachad-grc.com`
   - **TTL:** Automatic
6. Click the checkmark to save

---

### Google Domains / Squarespace

1. Log in to [Google Domains](https://domains.google.com) or [Squarespace Domains](https://domains.squarespace.com)
2. Select your domain
3. Click **DNS** in the sidebar
4. Scroll to **Custom records**
5. Click **Manage custom records**
6. Configure the record:
   - **Host name:** `trust` (or your chosen subdomain)
   - **Type:** CNAME
   - **TTL:** 3600
   - **Data:** `trust.gigachad-grc.com`
7. Click **Save**

---

## Step 3: Verify Your Configuration

After adding your DNS record, it can take anywhere from a few minutes to 48 hours for changes to propagate globally (though most changes take effect within 30 minutes).

### How to Check DNS Propagation

1. **Use an online tool:**
   - [DNS Checker](https://dnschecker.org) - Enter your full custom domain (e.g., `trust.yourcompany.com`)
   - [WhatsMyDNS](https://whatsmydns.net) - Check propagation across global servers

2. **Use command line:**
   ```bash
   # On Mac/Linux
   dig trust.yourcompany.com CNAME
   
   # On Windows
   nslookup -type=CNAME trust.yourcompany.com
   ```

3. **Test in browser:**
   - Visit `https://your-custom-domain.com`
   - You should see your Trust Center (once SSL is provisioned)

### Expected Results

When properly configured, the DNS lookup should return:
```
trust.yourcompany.com.  300  IN  CNAME  trust.gigachad-grc.com.
```

---

## SSL Certificate

GigaChad GRC automatically provisions a free SSL/TLS certificate for your custom domain using Let's Encrypt. This process:

- **Starts automatically** once DNS propagation is detected
- **Takes 5-15 minutes** to complete after DNS is verified
- **Renews automatically** before expiration

### SSL Status Indicators

| Status | Meaning |
|--------|---------|
| 🟡 Pending | DNS not yet propagated or SSL provisioning in progress |
| 🟢 Active | SSL certificate is active and your custom domain is ready |
| 🔴 Failed | DNS configuration issue - check your CNAME record |

> **Note:** During SSL provisioning, visitors may see a security warning. This is normal and will resolve once the certificate is issued.

---

## Troubleshooting

### "DNS not found" or "Site can't be reached"

**Possible causes:**
1. DNS changes haven't propagated yet (wait up to 48 hours)
2. CNAME record is incorrect
3. Wrong subdomain configured

**Solutions:**
- Verify your CNAME record points to `trust.gigachad-grc.com` (not `www.` or any other prefix)
- Check that the subdomain matches what you entered in GigaChad GRC
- Use [DNS Checker](https://dnschecker.org) to verify propagation

### "SSL Certificate Error" or "Not Secure"

**Possible causes:**
1. SSL certificate still provisioning
2. Cloudflare proxy enabled (orange cloud)
3. CAA record blocking Let's Encrypt

**Solutions:**
- Wait 15-30 minutes for SSL provisioning
- If using Cloudflare, ensure proxy is disabled (gray cloud)
- Check if your domain has a CAA record that restricts certificate authorities

### "Redirect Loop" or "Too Many Redirects"

**Possible causes:**
1. Conflicting redirect rules at your DNS provider
2. Cloudflare SSL mode set incorrectly

**Solutions:**
- Remove any redirect rules for the subdomain
- If using Cloudflare, set SSL mode to "Full" or "Full (strict)"

### Custom Domain Works But Shows Wrong Content

**Possible causes:**
1. Trust Center not enabled
2. Wrong organization linked

**Solutions:**
- Go to Trust Center Settings → General and ensure Trust Center is enabled
- Verify you're logged into the correct organization

---

## FAQ

### Can I use my root domain (e.g., yourcompany.com)?

We recommend using a subdomain (e.g., `trust.yourcompany.com`) for the following reasons:
- Root domains require A records instead of CNAME records
- Using your root domain may interfere with your main website
- Subdomains are easier to manage and troubleshoot

If you must use your root domain, contact our support team for assistance.

### Can I use multiple custom domains?

Currently, each Trust Center supports one custom domain. If you need multiple domains to point to your Trust Center, you can set up HTTP redirects at your DNS provider level.

### How long does DNS propagation take?

DNS propagation typically takes:
- **5-30 minutes** for most changes
- **Up to 24-48 hours** in some cases

The time depends on:
- Your DNS provider
- TTL settings of existing records
- Geographic location of users

### Will changing my custom domain cause downtime?

When changing your custom domain:
1. The old domain will stop working immediately
2. The new domain requires DNS propagation (5-30 minutes typically)
3. SSL certificate needs to be provisioned (5-15 minutes)

We recommend making changes during low-traffic periods and notifying stakeholders of the change in advance.

### Do I need to renew the SSL certificate?

No. GigaChad GRC automatically renews SSL certificates before they expire. No action is required on your part.

### Can I use a custom SSL certificate?

Currently, we only support auto-provisioned Let's Encrypt certificates. If you have specific SSL requirements (e.g., EV certificates, specific certificate authorities), please contact our support team.

### What if I don't have access to DNS settings?

Contact your IT administrator or the person who manages your domain. Provide them with this documentation and the CNAME record details:
- **Type:** CNAME
- **Host:** Your chosen subdomain
- **Value:** `trust.gigachad-grc.com`

### Is there a cost for custom domains?

Custom domain functionality is included in all GigaChad GRC plans at no additional cost. You're only responsible for your domain registration fees with your registrar.

---

## Need More Help?

If you're still experiencing issues:

1. **Check the in-app help** - Trust Center Settings has contextual guidance
2. **Review DNS records** - Double-check all values match exactly
3. **Contact support** - Reach out to our team at support@example.com

---

*Last updated: December 2025*

