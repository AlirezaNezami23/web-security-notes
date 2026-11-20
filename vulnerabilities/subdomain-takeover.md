# 🏴 Subdomain Takeover

Subdomain Takeover occurs when a DNS record (usually a **CNAME**, sometimes **NS**, **MX**, or **A**) still points to a **third-party service that is no longer provisioned** (a deleted S3 bucket, an unclaimed Heroku app, a removed GitHub Pages repo, etc.).

An attacker can **register/claim that same resource on the third-party service**, causing the target's own subdomain to serve attacker-controlled content — useful for phishing, cookie theft (same parent domain), bypassing CSP/CORS allowlists, or OAuth redirect abuse.

## 🧠 1. What is Subdomain Takeover?

Companies commonly point subdomains at managed platforms:

- `blog.company.com` → CNAME → `company.github.io`
- `shop.company.com` → CNAME → `shops.myshopify.com`
- `upload.company.com` → CNAME → `company.s3.amazonaws.com`
- `status.company.com` → CNAME → `company.statuspage.io`

When the underlying service (GitHub repo, S3 bucket, Shopify store, Heroku app, etc.) is deleted or the account is cancelled, **the DNS record is often forgotten and left dangling**. The hostname is still "claimed" by DNS but "unclaimed" on the service side — anyone who registers that same resource name on the service now effectively owns the subdomain.

## 📥 2. Vulnerable Scenario & Mechanics

### Example

```
dig blog.company.com CNAME
;; ANSWER SECTION:
blog.company.com.  300  IN  CNAME  company.github.io.
```

If `company.github.io` returns a GitHub Pages 404 ("There isn't a GitHub Pages site here"), it means the repo `company/company.github.io` doesn't exist (or the custom-domain file was removed) — an attacker can create that repo under their own account, add a `CNAME` file with `blog.company.com`, and the subdomain now resolves to the attacker's page.

## 📍 3. Where to Look (Discovery)

### 3.1 Enumerate All Subdomains

- Passive sources: `subfinder`, `amass` (passive mode), `crt.sh` (certificate transparency), `Shodan`, `SecurityTrails`, `VirusTotal`
- Active/brute-force: `amass enum -active`, `massdns` + wordlists (`dnsx`, `puredns`)
- Historical: Wayback Machine URLs, old marketing pages, archived subdomains that may still have DNS records even if the app behind them is long gone

```
subfinder -d company.com -all -o subs.txt
amass enum -passive -d company.com -o subs_amass.txt
```

### 3.2 Filter by Record Type (CNAME / NS / MX)

Only hostnames with a **dangling pointer** to an external service are candidates — resolve every subdomain and keep the ones with a CNAME (or NS) to a third-party domain:

```
dig upload.company.com any
dig app1.company.com any
dig blog.company.com any
```

Bulk version with `dnsx`:

```
cat subs.txt | dnsx -cname -resp -silent
```

### 3.3 Known Vulnerable Service Patterns

Cross-reference each CNAME target against a fingerprint list of services known to allow takeover. A few common ones to recognize by their CNAME pattern:

|Service|Typical CNAME target|Signal that it may be unclaimed|
|---|---|---|
|GitHub Pages|`*.github.io`|404 page "There isn't a GitHub Pages site here"|
|Heroku|`*.herokuapp.com`|"No such app"|
|AWS S3 (static site)|`*.s3.amazonaws.com` / `*.s3-website-*`|"NoSuchBucket" XML error|
|Shopify|`*.myshopify.com`|"Sorry, this shop is currently unavailable"|
|Fastly|`*.fastly.net`|"Fastly error: unknown domain"|
|Pantheon|`*.pantheonsite.io`|"404 error unknown site"|
|Statuspage.io|`*.statuspage.io`|"You are being redirected" / unclaimed page|
|UserVoice|`*.uservoice.com`|"This UserVoice subdomain is currently available!"|
|Zendesk|`*.zendesk.com`|"Help Center Closed"|
|Tilda|`*.tilda.ws`|"Please renew your subscription"|
|Cargo Collective|`*.cargocollective.com`|"404 Not Found"|
|WordPress.com|`*.wordpress.com`|"Do you want to register *.wordpress.com?"|

(This is not exhaustive — the `can-i-take-over-xyz` project maintains a continuously updated fingerprint list; check it before concluding a service isn't exploitable.)

## 🧪 4. Testing Methodology

### 4.1 Resolve & Fingerprint

For every CNAME target found in step 3.2, send an HTTP(S) request to the subdomain itself (not the target domain directly — the Host header matters) and compare the response body/status against the known "unclaimed" fingerprints above.

```
curl -s -i https://blog.company.com | head -n 30
curl -s -i -H "Host: blog.company.com" http://<resolved-ip>/
```

### 4.2 Automated Fingerprint Scanning

```
subzy run --targets subs.txt
nuclei -l subs.txt -t http/takeovers/
# or the tool shared with you:
subtake -l subs.txt
```

These tools match response bodies/headers against a signature database and flag likely-vulnerable hosts.

### 4.3 NS Takeover (less common, higher impact)

If a subdomain delegates to a third-party **NS** record (e.g., a cloud DNS zone) and that zone/account is no longer registered, an attacker can register the zone and answer **any** record for that subdomain (not just HTTP) — check NS records the same way:

```
dig company-sub.company.com NS
```

### 4.4 Dangling MX / Other Record Types

Less common but worth noting during the `any` query — a dangling MX can allow mail interception if the mail provider allows claiming the domain.

## ✅ 5. Confirmation & Classification Matrix

|Result Type|Description|Verification Criterion|
|---|---|---|
|**Confirmed (Claimable)**|Fingerprint matches a known "unclaimed resource" error AND the service allows self-service registration of that exact name|Successfully register the resource under a test account (only within authorized scope) and serve content from `https://blog.company.com`|
|**Likely (Fingerprint only)**|Response matches a known signature but ownership wasn't actively re-claimed (to stay within scope)|Documented fingerprint + CNAME still dangling at report time|
|**Not Exploitable**|CNAME resolves, but the service responds normally (resource still provisioned) or doesn't allow re-registration of arbitrary names|Live, functioning content returned|

_Always re-verify at report time — dangling records can be fixed or re-claimed by the legitimate owner between discovery and reporting, and some are transient (e.g., temporary deployment subdomains)._

## ⚒️ 6. Analysis Tools & Payload Repositories

- **subfinder / amass** — subdomain enumeration (passive & active)
- **dnsx / massdns / puredns** — bulk DNS resolution and CNAME extraction
- **subzy** — automated takeover fingerprint scanner
- **nuclei** (`http/takeovers/` templates) — signature-based detection at scale
- **subtake** — [github.com/AlirezaNezami23/subtake](https://github.com/AlirezaNezami23/subtake)
- **can-i-take-over-xyz** — community-maintained, up-to-date fingerprint/status database per service
- **crt.sh / Censys / Shodan** — certificate transparency & passive recon for forgotten subdomains

## 🛡️ 7. Prevention & Remediation

- ❌ **Remove Dangling DNS Records:** Delete the CNAME/NS/MX record immediately when decommissioning a third-party service or resource.
- ✅ **Asset Inventory:** Maintain an up-to-date inventory mapping every DNS record to its owning team/service, reviewed on a schedule.
- ✅ **Use Reserved/Owned Resource Names:** Where the platform supports it, keep the resource (e.g., S3 bucket, repo) reserved even if unused, rather than deleting it outright.
- ✅ **Automated Monitoring:** Continuously scan the organization's DNS zone for dangling CNAMEs (via tools like `subzy`/`nuclei` on a schedule, not just during pentests).
- ✅ **Least-Privilege DNS Access:** Restrict who can create DNS records, and require decommissioning tickets to include DNS cleanup steps.
