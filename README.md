
#  Web Application Reconnaissance

> A practical reconnaissance methodology for identifying an application's attack surface before vulnerability testing.

**Focus:** Passive Recon → Asset Discovery → Subdomain Enumeration → DNS → HTTP Probing → Technology Fingerprinting → URL/Parameter Discovery → Attack-Surface Mapping

**Platforms:** Kali Linux + Windows
**Primary tools:** `whois`, `dig`, `nslookup`, `host`, `amass`, `subfinder`, `assetfinder`, `theHarvester`, `crt.sh`, `dnsrecon`, `nmap`, `whatweb`, `httpx`, `waybackurls`, `gau`, `katana`, Burp Suite, OWASP ZAP

>  **Authorization:** Run active enumeration, scanning, crawling, and parameter testing only against systems you own or are explicitly authorized to assess. Passive OSINT is generally less intrusive, but scope rules still apply.

---

#  Table of Contents

1. [What Is Reconnaissance?](#-what-is-reconnaissance)
2. [Why Recon Is Important](#-why-recon-matters)
3. [Recon Methodology](#-complete-recon-methodology)
4. [Phase 0 — Define Scope](#-phase-0--define-scope)
5. [Phase 1 — Passive Recon](#-phase-1--passive-recon)
6. [WHOIS](#-whois)
7. [DNS Enumeration](#-dns-enumeration)
8. [Certificate Transparency](#-certificate-transparency)
9. [Search Engine Recon](#-search-engine-recon)
10. [Technology Fingerprinting](#-technology-fingerprinting)
11. [Subdomain Enumeration](#-subdomain-enumeration)
12. [Merging and Deduplicating Results](#-merging-and-deduplicating-results)
13. [DNS Resolution](#-dns-resolution)
14. [HTTP Probing](#-http-probing)
15. [Filtering 200/300 Responses](#-filtering-live-urls)
16. [Port and Service Discovery](#-port-and-service-discovery)
17. [URL Discovery](#-url-discovery)
18. [Parameter Discovery](#-parameter-discovery)
19. [Identifying Interesting Parameters](#-identifying-interesting-parameters)
20. [Burp Suite Recon](#-burp-suite-recon)
21. [Windows Workflow](#-windows-workflow)
22. [Kali Workflow](#-kali-workflow)
23. [Complete Automation Pipeline](#-complete-recon-pipeline)
24. [Recon Folder Structure](#-recommended-folder-structure)
25. [Recon Checklist](#-complete-recon-checklist)
26. [Common Mistakes](#-common-mistakes)
27. [Final Attack-Surface Diagram](#-final-attack-surface-diagram)

---

#  What Is Reconnaissance?

Reconnaissance is the process of **collecting information about a target before security testing**.

The goal is not immediately to exploit something.

The goal is to understand:

```text
WHO / WHAT IS THE TARGET?
        ↓
WHAT ASSETS EXIST?
        ↓
WHAT SERVICES ARE EXPOSED?
        ↓
WHAT APPLICATIONS EXIST?
        ↓
WHAT TECHNOLOGIES ARE USED?
        ↓
WHAT URLS EXIST?
        ↓
WHAT PARAMETERS EXIST?
        ↓
WHAT SHOULD BE TESTED?
```

OWASP describes attack-surface identification as discovering applications, domains, virtual hosts, externally exposed services, DNS information, subdomains, non-standard ports, and certificate information.

---

# 🎯 Why Recon Matters

A common mistake is:

```text
Target
  ↓
Open homepage
  ↓
Start attacking
```

Professional testing is closer to:

```text
                 TARGET
                    │
                    ▼
             PASSIVE RECON
                    │
                    ▼
             ASSET DISCOVERY
                    │
                    ▼
           SUBDOMAIN ENUMERATION
                    │
                    ▼
             DNS ENUMERATION
                    │
                    ▼
              HTTP PROBING
                    │
                    ▼
         TECHNOLOGY FINGERPRINTING
                    │
                    ▼
              URL DISCOVERY
                    │
                    ▼
           PARAMETER DISCOVERY
                    │
                    ▼
             ATTACK SURFACE
                    │
                    ▼
            SECURITY TESTING
```

A good recon process can reveal forgotten, staging, development, API, authentication, or administrative assets that may not be visible from the main website.

---

#  Recon Has Two Main Categories

## Passive Recon

Information is obtained without directly interacting with the target infrastructure where possible.

Examples:

```text
WHOIS
Certificate Transparency
Search engines
Public DNS databases
Public repositories
Passive subdomain sources
Public documentation
Public breach/metadata sources where legally appropriate
```

---

## Active Recon

You directly interact with the target.

Examples:

```text
DNS queries
HTTP requests
Port scanning
Web crawling
Technology detection
Directory discovery
Service enumeration
```

### Difference

```text
PASSIVE
Internet / Public Sources
        │
        ▼
     Information
        │
        ▼
    Target model


ACTIVE
Tester
  │
  ▼
Target
  │
  ▼
Response
  │
  ▼
Information
```

OWASP recommends passive techniques early in reconnaissance because they can reduce interaction with target infrastructure.

---

#  Complete Recon Methodology

```text
┌───────────────────────────┐
│       SCOPE / ROE         │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│       PASSIVE RECON       │
│ WHOIS / CT / Search / OSINT│
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│    SUBDOMAIN DISCOVERY    │
│ Subfinder / Amass / etc.  │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│      DNS RESOLUTION       │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│      HTTP PROBING         │
│          httpx            │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│    TECHNOLOGY FINGERPRINT │
│ WhatWeb / httpx / Wappalyzer│
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│    PORT / SERVICE ENUM    │
│          Nmap             │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│       URL DISCOVERY       │
│ GAU / Wayback / Katana    │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│   PARAMETER DISCOVERY     │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│    ATTACK SURFACE MAP     │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│     SECURITY TESTING      │
└───────────────────────────┘
```

---

# 0️⃣ Phase 0 — Define Scope

Before running tools, define:

```text
Target:
example.com

In scope:
*.example.com

Out of scope:
admin.example.com
third-party.example.net

Testing:
Web application
API
DNS
```

Create:

```bash
mkdir -p recon/{passive,dns,subdomains,http,ports,urls,params,notes}
```

Then:

```text
recon/
├── passive/
├── dns/
├── subdomains/
├── http/
├── ports/
├── urls/
├── params/
└── notes/
```

---

# 1️ Phase 1 — Passive Recon

Start without directly scanning the application.

---

#  WHOIS

WHOIS can provide domain registration and registrar information where publicly available.

### Kali

```bash
whois example.com
```

Look for:

```text
Registrar
Name servers
Registration dates
Domain status
Organization information
```

Do not assume every field will be available; privacy services commonly obscure registrant information.

---

#  DNS Recon

Important DNS records include:

```text
A
AAAA
CNAME
MX
NS
TXT
SOA
```

### dig

```bash
dig example.com
```

A record:

```bash
dig example.com A
```

MX:

```bash
dig example.com MX
```

NS:

```bash
dig example.com NS
```

TXT:

```bash
dig example.com TXT
```

CNAME:

```bash
dig sub.example.com CNAME
```

---

#  Windows DNS Commands

Windows includes:

```cmd
nslookup example.com
```

Specific record:

```cmd
nslookup -type=MX example.com
```

Nameservers:

```cmd
nslookup -type=NS example.com
```

You can also use PowerShell:

```powershell
Resolve-DnsName example.com
```

---

#  Certificate Transparency

TLS certificates can reveal hostnames that are not obvious from the main website.

Example:

```text
example.com
api.example.com
dev.example.com
staging.example.com
mail.example.com
```

Certificate Transparency is explicitly included by OWASP as a useful source during attack-surface identification.

A common public source is:

```text
crt.sh
```

Example query:

```text
%.example.com
```

Export discovered names and add them to:

```text
subdomains/passive_ct.txt
```

---

#  Search Engine Recon

Search engines can reveal:

```text
Public documents
Login pages
Subdomains
Development references
API documentation
Error pages
Technology information
```

Examples:

```text
site:example.com
site:example.com login
site:example.com api
site:example.com admin
site:example.com filetype:pdf
```

These searches should be treated as **discovery**, not as permission to access restricted material.

OWASP's information-gathering methodology includes search-engine reconnaissance and information leakage review.

---

#  GitHub / Public Repository Recon

Search only public information within the authorized assessment scope.

Look for:

```text
Domain names
API documentation
Subdomains
Public JavaScript
Technology references
Configuration examples
Development endpoints
```

Be careful with credentials or secrets discovered accidentally. Do not use exposed credentials unless the engagement explicitly authorizes that activity; report the exposure instead.

---

#  2️⃣ Subdomain Enumeration

Subdomain enumeration is one of the most important parts of recon.

Example:

```text
example.com
     │
     ├── www.example.com
     ├── api.example.com
     ├── app.example.com
     ├── dev.example.com
     ├── staging.example.com
     ├── test.example.com
     └── admin.example.com
```

OWASP identifies subdomain discovery as an important component of attack-surface identification.

---

#  Subfinder

Subfinder is designed for **passive subdomain enumeration** using public sources.

Basic:

```bash
subfinder -d example.com -silent
```

Save:

```bash
subfinder -d example.com -silent -o subfinder.txt
```

Use all available sources:

```bash
subfinder -d example.com -all -silent -o subfinder-all.txt
```

ProjectDiscovery documents `-all`, source selection, recursive discovery, filtering, and output options.

---

#  Amass

Amass is useful for broader attack-surface and DNS discovery.

```bash
amass enum -passive -d example.com
```

Save:

```bash
amass enum -passive -d example.com -o amass.txt
```

---

#  Assetfinder

```bash
assetfinder --subs-only example.com
```

Save:

```bash
assetfinder --subs-only example.com > assetfinder.txt
```

---

#  Findomain

If installed:

```bash
findomain -t example.com
```

---

#  DNSRecon

DNSRecon can perform DNS enumeration.

```bash
dnsrecon -d example.com
```

OWASP lists `amass`, `subfinder`, `dnsrecon`, `fierce`, `dig`, and `nslookup` among commonly used DNS enumeration tools.

---

#  Use Multiple Sources

Don't rely on one subdomain tool.

Example:

```text
Subfinder
    +
Amass
    +
Assetfinder
    +
Findomain
    +
Certificate Transparency
    +
Public DNS
        ↓
   Merge Results
        ↓
   Remove Duplicates
        ↓
   Resolve DNS
```

Different sources can produce different results.

---

#  3️⃣ Merge All Subdomain Results

Suppose:

```text
subfinder.txt
amass.txt
assetfinder.txt
findomain.txt
crt.txt
```

Merge:

```bash
cat subfinder.txt amass.txt assetfinder.txt findomain.txt crt.txt > all-subdomains.txt
```

Remove duplicates:

```bash
sort -u all-subdomains.txt -o all-subdomains.txt
```

Now:

```text
all-subdomains.txt
```

contains your consolidated list.

---

#  Clean the Results

You may encounter:

```text
http://api.example.com
https://api.example.com
api.example.com
```

For DNS enumeration, normalize to:

```text
api.example.com
```

Example using a simple text-processing pipeline:

```bash
sed 's#https\?://##' all-subdomains.txt | sed 's#/.*##' | sort -u > normalized-subdomains.txt
```

Always review the output before using it in subsequent tools.

---

#  4️⃣ DNS Resolution

Not every discovered hostname is currently resolvable.

Check:

```bash
dnsx -l normalized-subdomains.txt -silent -o resolved.txt
```

If `dnsx` is unavailable:

```bash
while read sub; do
    dig +short "$sub" | grep -q . && echo "$sub"
done < normalized-subdomains.txt
```

This creates a smaller set of hosts that currently resolve.

---

#  5️⃣ HTTP Probing With HTTPX

ProjectDiscovery's `httpx` can probe host lists for HTTP services and collect information such as status codes, titles, content types, technologies, redirects, and other metadata.

Basic:

```bash
httpx -l resolved.txt -silent -o live.txt
```

Include status:

```bash
httpx -l resolved.txt -status-code -silent -o live-status.txt
```

Include title:

```bash
httpx -l resolved.txt -title -status-code -silent -o live-details.txt
```

Technology detection:

```bash
httpx -l resolved.txt -title -status-code -tech-detect -silent -o live-tech.txt
```

Example output:

```text
https://api.example.com [200] [API Portal] [nginx]
https://dev.example.com [403] [Development] [Cloudflare]
https://old.example.com [301] [...]
```

ProjectDiscovery specifically documents chaining `subfinder` into `httpx` for asset discovery and HTTP probing.

---

#  6️⃣ Filter Live 200/300 Responses

A useful reconnaissance dataset separates response classes.

### 200

```text
200 OK
```

Usually means the resource returned successfully.

### 3xx

```text
301
302
307
308
```

Usually indicates redirects.

### 4xx

```text
401
403
404
```

These are still valuable.

**Do not automatically discard 401/403/404.**

A `403` endpoint can still reveal:

```text
Application exists
Endpoint exists
Technology
Authentication boundary
WAF behavior
```

---

# Extract 200 Responses

If your `httpx` output contains status codes:

```bash
grep '\[200\]' live-details.txt > status-200.txt
```

Extract 3xx:

```bash
grep -E '\[(301|302|303|307|308)\]' live-details.txt > status-300.txt
```

Combine:

```bash
cat status-200.txt status-300.txt > live-200-300.txt
```

For cleaner URL-only output, generate a URL list separately:

```bash
httpx -l resolved.txt -silent -o live-urls.txt
```

Then use the detailed file for status classification.

---

#  Don't Ignore 401/403

Create a separate file:

```bash
grep -E '\[(401|403)\]' live-details.txt > restricted.txt
```

This can be valuable during later authorized testing.

Your inventory should therefore look like:

```text
live/
├── 200.txt
├── 300.txt
├── 401.txt
├── 403.txt
└── other.txt
```

---

#  7️⃣ WhatWeb — Technology Fingerprinting

WhatWeb identifies technologies used by websites, including CMSs, web servers, frameworks, JavaScript libraries, and other components. Kali currently provides WhatWeb as a package.

Basic:

```bash
whatweb https://example.com
```

More detailed:

```bash
whatweb -v https://example.com
```

Aggressive identification:

```bash
whatweb -a 3 https://example.com
```

Multiple targets:

```bash
whatweb -i live-urls.txt
```

You might discover:

```text
Apache
Nginx
WordPress
PHP
React
jQuery
Laravel
Cloudflare
```

### Why this matters

Technology fingerprinting helps you understand:

```text
Web Server
     ↓
Framework
     ↓
CMS
     ↓
JavaScript
     ↓
Application Architecture
```

OWASP notes that identifying technologies and application components can significantly reduce testing effort.

---

#  8️⃣ Nmap

Nmap is primarily used for host, port, and service discovery.

Basic:

```bash
nmap example.com
```

Service detection:

```bash
nmap -sV example.com
```

Common web ports:

```bash
nmap -p 80,443,8080,8443 example.com
```

More comprehensive authorized assessment:

```bash
nmap -sV -sC example.com
```

Output may reveal:

```text
22/tcp   SSH
80/tcp   HTTP
443/tcp  HTTPS
8080/tcp HTTP proxy
```

### Important

Do not blindly scan every discovered IP.

First verify:

```text
Is the IP in scope?
Is the service owned by the target?
Is active scanning allowed?
```

A domain can resolve to shared infrastructure or third-party services.

---

#  9️⃣ URL Discovery

Once live hosts are identified, discover URLs and application paths.

Useful sources:

```text
Wayback Machine
GAU
Katana
Burp Suite
Application JavaScript
Robots.txt
Sitemap.xml
Public documentation
```

---

#  Waybackurls

Example:

```bash
waybackurls example.com > wayback.txt
```

For a list of authorized subdomains:

```bash
cat live-urls.txt | waybackurls > wayback-all.txt
```

Historical URLs can reveal:

```text
Old endpoints
Old parameters
Old APIs
Old files
Old application paths
```

---

#  GAU

GetAllURLs can retrieve URLs from public sources.

```bash
gau example.com > gau.txt
```

Combine:

```bash
cat wayback.txt gau.txt | sort -u > historical-urls.txt
```

---

#  Katana

Katana is useful for crawling authorized web applications.

Basic:

```bash
katana -u https://example.com
```

Save:

```bash
katana -u https://example.com -o katana.txt
```

For a list:

```bash
katana -list live-urls.txt -o crawled.txt
```

---

#  10️⃣ JavaScript Discovery

JavaScript files are extremely useful during recon.

Find:

```text
.js
```

Example:

```bash
grep -Ei '\.js([?#]|$)' all-urls.txt > javascript-files.txt
```

JavaScript may reveal:

```text
API endpoints
Routes
Parameter names
Feature flags
Environment references
Third-party integrations
```

Do not treat client-side JavaScript as a trusted security boundary.

---

#  11️⃣ Parameter Discovery

Now we move from:

```text
HOST DISCOVERY
      ↓
URL DISCOVERY
      ↓
PARAMETER DISCOVERY
```

Example:

```text
https://example.com/search?q=phone
                         ↑
                      parameter
```

Other examples:

```text
?id=123
?page=2
?search=test
?category=1
?redirect=/home
?url=https://example.com
?file=document.pdf
?lang=en
```

---

#  Why Parameters Matter

Parameters represent inputs that influence application behavior.

```text
URL
 │
 ├── Path
 │
 └── Parameters
       │
       ├── id
       ├── q
       ├── page
       ├── redirect
       └── file
```

These inputs can become candidates for security testing.

**Finding a parameter is not evidence of a vulnerability.**

---

#  Parameter Categories

## Object Parameters

```text
?id=
?userId=
?accountId=
?orderId=
?documentId=
```

Useful for authorized access-control testing.

---

## Search Parameters

```text
?q=
?query=
?search=
?keyword=
```

Potentially relevant to input-handling testing.

---

## URL Parameters

```text
?url=
?redirect=
?next=
?return=
```

Potentially relevant to redirect/SSRF-style testing depending on how the server processes them.

---

## File Parameters

```text
?file=
?path=
?document=
?template=
```

Potentially relevant to file/path handling.

---

## Pagination

```text
?page=
?limit=
?offset=
```

Potentially relevant to authorization, business logic, and data exposure testing.

---

#  12️⃣ Extract Parameterized URLs

From a URL list:

```bash
grep '?' all-urls.txt > parameterized.txt
```

Sort:

```bash
sort -u parameterized.txt -o parameterized.txt
```

Count:

```bash
wc -l parameterized.txt
```

Example:

```text
https://example.com/search?q=test
https://example.com/product?id=123
https://example.com/page?page=2
```

---

#  Remove Static URLs

You can create a cleaner candidate set:

```bash
grep -E '\?.+=.+' parameterized.txt | sort -u > parameterized-clean.txt
```

---

#  Parameter Discovery Workflow

```text
Historical URLs
       +
Crawled URLs
       +
Burp URLs
       +
JavaScript URLs
       ↓
    Merge
       ↓
    Deduplicate
       ↓
Parameterized URLs
       ↓
Classify Parameters
       ↓
Security Testing
```

---

#  13️⃣ Finding Parameters for Security Testing

The objective is **not**:

```text
"Find a URL and immediately inject payloads."
```

The professional process is:

```text
Discover
   ↓
Understand
   ↓
Classify
   ↓
Validate
   ↓
Test
   ↓
Document
```

For example:

```text
?id=123
```

First determine:

```text
What is 123?
Who owns object 123?
Does changing it affect authorization?
What response is returned?
```

For:

```text
?q=phone
```

determine:

```text
Where does q go?
Search?
HTML?
Database?
JavaScript?
```

Only then select appropriate security tests.

---

#  Common Parameter → Test Mapping

| Parameter   | Potential Area                                           |
| ----------- | -------------------------------------------------------- |
| `id`        | Access control / IDOR                                    |
| `userId`    | Access control                                           |
| `accountId` | Access control                                           |
| `orderId`   | Access control                                           |
| `q`         | Input handling / XSS / injection                         |
| `search`    | Input handling                                           |
| `query`     | Input handling                                           |
| `redirect`  | Redirect validation                                      |
| `next`      | Redirect validation                                      |
| `url`       | URL handling / SSRF depending on behavior                |
| `file`      | File/path handling                                       |
| `path`      | File/path handling                                       |
| `page`      | Business logic / data exposure                           |
| `sort`      | Input validation / injection depending on implementation |

Again:

> **A parameter is only a testing candidate, not proof of a vulnerability.**

---

#  SQL Injection Testing Preparation

During recon, identify URLs such as:

```text
/product?id=123
/search?query=phone
/category?id=5
```

Then record:

```text
Endpoint
Parameter
HTTP method
Authentication requirement
Response behavior
```

Example inventory:

```text
Endpoint:
GET /product

Parameter:
id

Type:
Numeric identifier

Auth:
Public

Potential test:
Input validation / injection testing
```

Actual SQL injection testing should happen only after the endpoint is understood and the target is authorized.

---

#  XSS Testing Preparation

Look for parameters that may be reflected or processed by the application:

```text
?q=
?search=
?name=
?message=
?comment=
```

Then determine where the input appears:

```text
Input
  ↓
Server response?
  ↓
HTML?
  ↓
Attribute?
  ↓
JavaScript?
  ↓
DOM?
```

This tells you which XSS category may be relevant.

---

#  14️⃣ Attack-Surface Prioritization

Not every URL has equal value.

Prioritize:

```text
1. Authentication
2. Authorization
3. Admin interfaces
4. APIs
5. File upload
6. Account management
7. Payment/business functions
8. URL-fetching functionality
9. Search/input endpoints
10. Legacy applications
11. Development/staging systems
12. Old API versions
```

Example:

```text
api.example.com
        ↓
HIGH PRIORITY

dev.example.com
        ↓
HIGH PRIORITY

www.example.com/static/
        ↓
LOWER PRIORITY
```

The exact priority depends on scope and application architecture.

---

#  15️⃣ Burp Suite Recon

Burp Suite is especially useful once you interact with an authorized web application.

Workflow:

```text
Browser
   │
   ▼
Burp Proxy
   │
   ├── Requests
   ├── Responses
   ├── Parameters
   ├── Cookies
   └── APIs
```

Look at:

```text
Proxy → HTTP history
```

Identify:

```text
GET
POST
PUT
PATCH
DELETE
WebSocket
```

Then map:

```text
Endpoint
Method
Parameters
Authentication
Response
```

---

#  16️⃣ Build an Attack-Surface Inventory

Create a table:

| Host    | URL         | Status | Technology | Parameters | Priority |
| ------- | ----------- | -----: | ---------- | ---------- | -------- |
| `www`   | `/`         |    200 | Nginx      | None       | Medium   |
| `api`   | `/v1/users` |    200 | API        | `id`       | High     |
| `app`   | `/search`   |    200 | React      | `q`        | High     |
| `admin` | `/login`    |    403 | Nginx      | None       | High     |
| `dev`   | `/`         |    200 | Framework  | Various    | High     |

This becomes the bridge between:

```text
RECON
  ↓
VULNERABILITY TESTING
```

---

# 🪟 Windows Recon Workflow

Useful Windows tools:

```text
WHOIS
nslookup
Resolve-DnsName
Nmap
Burp Suite
OWASP ZAP
WhatWeb
Amass
Subfinder
HTTPX
GAU
Katana
```

Example:

```powershell
Resolve-DnsName example.com
```

Nmap:

```powershell
nmap -sV example.com
```

Subfinder:

```powershell
subfinder -d example.com -silent
```

HTTPX:

```powershell
httpx -l subdomains.txt -status-code -title
```

The ProjectDiscovery tools provide Windows binaries/releases as well as other installation options; follow their current documentation for installation.

---

#  Kali Linux Recon Workflow

Typical Kali workflow:

```bash
whois
dig
dnsrecon
subfinder
amass
assetfinder
findomain
dnsx
httpx
whatweb
nmap
gau
waybackurls
katana
burpsuite
```

Kali already packages many security tools, while ProjectDiscovery tools can be installed through their supported installation methods.

---

#  17️⃣ Complete Recon Pipeline

For an authorized target:

```bash
# 1. Passive subdomain discovery
subfinder -d example.com -all -silent -o subfinder.txt

# 2. Additional discovery
assetfinder --subs-only example.com > assetfinder.txt

# 3. Merge
cat subfinder.txt assetfinder.txt > all-subdomains.txt

# 4. Deduplicate
sort -u all-subdomains.txt -o all-subdomains.txt

# 5. Probe HTTP services
httpx -l all-subdomains.txt -status-code -title -tech-detect -silent -o live.txt

# 6. Save URLs separately
httpx -l all-subdomains.txt -silent -o live-urls.txt

# 7. Extract 200
grep '\[200\]' live.txt > status-200.txt

# 8. Extract redirects
grep -E '\[(301|302|303|307|308)\]' live.txt > status-300.txt

# 9. Keep restricted endpoints separately
grep -E '\[(401|403)\]' live.txt > restricted.txt

# 10. Historical URL discovery
cat live-urls.txt | waybackurls > wayback.txt

# 11. GAU
cat live-urls.txt | gau > gau.txt

# 12. Merge URLs
cat wayback.txt gau.txt | sort -u > all-urls.txt

# 13. Parameterized URLs
grep -E '\?.+=.+' all-urls.txt | sort -u > parameterized.txt
```

The exact flags available can change with tool versions, so check `tool -h` and the current documentation before running a workflow. ProjectDiscovery documents the current Subfinder and HTTPX options.

---

#  18️⃣ Better Recon Pipeline

A mature workflow is not simply "run everything."

Use:

```text
                 SCOPE
                   │
                   ▼
             PASSIVE OSINT
                   │
          ┌────────┴────────┐
          ▼                 ▼
      DNS / CT          Search / Public
          │                 │
          └────────┬────────┘
                   ▼
             SUBDOMAINS
                   │
                   ▼
               RESOLVE
                   │
                   ▼
              HTTPX
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
      200         300       401/403
       │           │           │
       └───────────┼───────────┘
                   ▼
            TECHNOLOGY
             FINGERPRINT
                   │
                   ▼
              URL CRAWL
                   │
                   ▼
           HISTORICAL URLS
                   │
                   ▼
           PARAMETER EXTRACTION
                   │
                   ▼
          ATTACK-SURFACE MAP
                   │
                   ▼
          MANUAL VALIDATION
```

---

#  19️⃣ Recommended Recon Folder

```text
recon/
│
├── scope.txt
│
├── passive/
│   ├── whois.txt
│   ├── dns.txt
│   ├── crt.txt
│   ├── search.txt
│   └── osint.txt
│
├── subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   ├── findomain.txt
│   └── all-subdomains.txt
│
├── dns/
│   ├── resolved.txt
│   └── dns-records.txt
│
├── http/
│   ├── live.txt
│   ├── live-urls.txt
│   ├── status-200.txt
│   ├── status-300.txt
│   └── restricted.txt
│
├── ports/
│   └── nmap.txt
│
├── urls/
│   ├── wayback.txt
│   ├── gau.txt
│   ├── katana.txt
│   └── all-urls.txt
│
├── params/
│   ├── parameterized.txt
│   ├── javascript.txt
│   └── interesting-params.txt
│
└── notes/
    ├── technologies.md
    ├── endpoints.md
    └── attack-surface.md
```

---

#  20️⃣ Recon Evidence

Good recon should produce evidence.

Instead of:

```text
"I found 200 subdomains."
```

Document:

```text
Source
  ↓
Command
  ↓
Output
  ↓
Validation
  ↓
Final asset
```

Example:

```text
Source:
Subfinder

Discovery:
api.example.com

Validation:
HTTPX → 200

Technology:
Nginx / API framework

URL discovery:
https://api.example.com/v1/

Parameter:
?id=

Priority:
HIGH
```

---

#  21️⃣ Recon-to-Vulnerability Flow

Recon does not prove vulnerabilities.

It produces **test candidates**.

```text
Recon
 │
 ├── api.example.com
 │       ↓
 │    API testing
 │
 ├── /search?q=
 │       ↓
 │    Input testing
 │
 ├── /product?id=
 │       ↓
 │    Access-control / injection testing
 │
 ├── /redirect?url=
 │       ↓
 │    URL-handling testing
 │
 └── /upload
         ↓
      File-upload testing
```

This is the correct relationship:

```text
RECON → CANDIDATE → VALIDATION → FINDING
```

Not:

```text
RECON → ASSUMPTION → VULNERABILITY
```

---

#  22️⃣ Common Recon Mistakes

##  Mistake 1 — Using only one subdomain tool

Better:

```text
Subfinder
+
Amass
+
Assetfinder
+
CT
```

---

##  Mistake 2 — Keeping duplicates

Always normalize:

```bash
sort -u
```

---

##  Mistake 3 — Only keeping 200

Do not discard:

```text
301
302
401
403
```

A restricted endpoint can still be important.

---

##  Mistake 4 — Ignoring historical URLs

Old endpoints can reveal:

```text
Legacy APIs
Old parameters
Deprecated functionality
Old application versions
```

---

##  Mistake 5 — Treating every parameter as vulnerable

A parameter is only:

```text
TEST CANDIDATE
```

You need evidence before calling it a vulnerability.

---

##  Mistake 6 — Scanning third-party infrastructure

A DNS record may point to:

```text
Cloudflare
AWS
GitHub
Azure
Third-party SaaS
CDN
```

Confirm scope before active testing.

---

##  Mistake 7 — Running aggressive tools too early

Good order:

```text
Passive
  ↓
Low-noise discovery
  ↓
Validation
  ↓
Active enumeration
  ↓
Security testing
```

---

#  23️⃣ Defensive Value of Recon

Recon is not only for attackers.

Defenders can use the same methodology to answer:

```text
What assets do we expose?
What subdomains exist?
Which services are public?
Which technologies are outdated?
Are staging systems exposed?
Are forgotten APIs online?
Are old endpoints still reachable?
```

Therefore:

```text
External Attack Surface Management
             ↓
        Asset Discovery
             ↓
          Inventory
             ↓
       Risk Prioritization
             ↓
         Remediation
```

---

#  24️⃣ Complete Recon Checklist

```text
SCOPE
[ ] Define authorized domains
[ ] Define authorized IP ranges
[ ] Identify exclusions
[ ] Record rules of engagement

PASSIVE RECON
[ ] WHOIS
[ ] DNS records
[ ] Certificate Transparency
[ ] Search engines
[ ] Public documentation
[ ] Public repositories
[ ] Technology references

SUBDOMAIN ENUMERATION
[ ] Subfinder
[ ] Amass
[ ] Assetfinder
[ ] Findomain
[ ] CT results
[ ] Merge results
[ ] Deduplicate

DNS
[ ] Resolve discovered hosts
[ ] Identify A records
[ ] Identify AAAA records
[ ] Identify CNAME records
[ ] Identify MX records
[ ] Identify NS records
[ ] Review TXT records

HTTP
[ ] Probe HTTP/HTTPS
[ ] Collect status codes
[ ] Collect titles
[ ] Detect technologies
[ ] Save live URLs
[ ] Separate 200
[ ] Separate 300
[ ] Keep 401/403 separately

NETWORK
[ ] Identify in-scope IPs
[ ] Port scan
[ ] Service detection
[ ] Record exposed services

WEB DISCOVERY
[ ] Crawl application
[ ] Wayback URLs
[ ] GAU
[ ] Katana
[ ] Robots.txt
[ ] Sitemap
[ ] JavaScript files
[ ] API documentation

PARAMETERS
[ ] Extract query parameters
[ ] Identify object IDs
[ ] Identify search parameters
[ ] Identify URL parameters
[ ] Identify file/path parameters
[ ] Identify API parameters

FINAL MAPPING
[ ] Build asset inventory
[ ] Classify technologies
[ ] Prioritize endpoints
[ ] Create attack-surface map
[ ] Record evidence
[ ] Prepare vulnerability-testing candidates
```

---

#  25️⃣ Final Attack-Surface Diagram

```text
                         TARGET
                           │
                           ▼
                 ┌──────────────────┐
                 │   PASSIVE RECON  │
                 └────────┬─────────┘
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
        WHOIS          DNS / CT       SEARCH
           │              │              │
           └──────────────┼──────────────┘
                          ▼
                ┌─────────────────┐
                │ SUBDOMAIN ENUM   │
                └────────┬────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
          Subfinder    Amass    Assetfinder
              │          │          │
              └──────────┼──────────┘
                         ▼
                   DEDUPLICATE
                         │
                         ▼
                  DNS RESOLUTION
                         │
                         ▼
                      HTTPX
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
         200            300           401/403
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                TECHNOLOGY FINGERPRINT
                         │
                  WhatWeb / HTTPX
                         │
                         ▼
                  PORT / SERVICE
                       NMAP
                         │
                         ▼
                    URL DISCOVERY
              ┌──────────┼──────────┐
              ▼          ▼          ▼
          Wayback       GAU       Katana
              │          │          │
              └──────────┼──────────┘
                         ▼
                  URL DEDUPLICATION
                         │
                         ▼
                  PARAMETER DISCOVERY
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
        id/user       q/search      url/redirect
           │             │             │
           ▼             ▼             ▼
      Access Control   Input Tests   URL Handling
                         │
                         ▼
                ATTACK-SURFACE MAP
                         │
                         ▼
                  SECURITY TESTING
                         │
                         ▼
                       REPORT
```

---

#  Final Principle

The goal of professional reconnaissance is not to run the maximum number of tools.

The goal is to build the **most accurate attack-surface map with the least unnecessary interaction**.

```text
RECON
  ↓
DISCOVER
  ↓
VERIFY
  ↓
CLASSIFY
  ↓
PRIORITIZE
  ↓
TEST
  ↓
VALIDATE
  ↓
REPORT
```

### Remember:

> **Discover first. Understand second. Test third.**

A strong recon phase turns a large domain into a structured inventory of:

```text
Domains
   ↓
Subdomains
   ↓
IPs
   ↓
Ports
   ↓
Services
   ↓
Technologies
   ↓
URLs
   ↓
Parameters
   ↓
Security-Test Candidates
```

That is the foundation for professional VAPT and web-application security testing.

---

##  References

* OWASP Web Security Testing Guide — Information Gathering and Attack Surface Identification.
* ProjectDiscovery Subfinder documentation — passive subdomain enumeration and output/filtering options.
* ProjectDiscovery HTTPX documentation — HTTP probing, status codes, titles, technologies, and output.
* Kali Linux WhatWeb documentation.
* OWASP Web Security Testing Guide — Web application fingerprinting.
