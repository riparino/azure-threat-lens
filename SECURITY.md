# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Active security fixes |
| < 0.2   | ❌ No longer supported |

Only the latest minor release receives security patches. Users on older versions should upgrade.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository (**Security → Report a vulnerability**).

### What to include

- **Description** — what the vulnerability is and what an attacker could achieve
- **Steps to reproduce** — a minimal, reliable reproduction path
- **Affected versions** — which version(s) you tested against
- **Environment** — OS, Python version, relevant configuration
- **Suggested fix** — if you have one (optional but appreciated)

Providing clear reproduction steps significantly speeds up triage and remediation.

---

## Disclosure Policy

| Stage | Target timeframe |
|-------|-----------------|
| Acknowledgement | Within **72 hours** of report |
| Triage & severity assessment | Within **7 days** |
| Fix developed and reviewed | Within **45 days** for critical/high; **90 days** for medium/low |
| Public advisory published | Coordinated with reporter; default **90 days** from report |

We practise coordinated disclosure. We will work with reporters to agree on an appropriate publication date and will credit researchers in the advisory unless they prefer to remain anonymous.

If a fix is not feasible within the stated timeline, we will communicate the delay and revised timeline to the reporter before any public disclosure.

---

## Scope

The following are considered in-scope vulnerabilities for this project:

- **Credential exposure** — any path by which Azure credentials, client secrets, or threat intel API keys could be logged, written to disk unencrypted, or leaked in error output
- **Injection vulnerabilities** — command injection, SSRF, or template injection via user-controlled input passed to Azure APIs, CLI arguments, or Jinja2 templates
- **Insecure API communication** — TLS verification bypass, cleartext credential transmission, or improper certificate handling in `httpx` clients
- **Authentication bypass** — logic flaws allowing API calls to proceed without valid Azure credentials
- **Sensitive data in logs** — secrets or PII appearing in structured log output at any log level
- **Dependency vulnerabilities** — critical CVEs in direct dependencies that are exploitable through this tool's exposed surface (note: Dependabot handles routine updates)
- **Privilege escalation in multi-tenant mode** — cross-tenant data leakage in Azure Lighthouse workspace federation

---

## Out of Scope

The following are **not** considered in-scope for this security policy:

- Rate limiting or abuse of third-party threat intelligence APIs (VirusTotal, GreyNoise, AbuseIPDB) — report these to the respective providers
- Vulnerabilities that require physical access to the machine running the tool
- Denial-of-service against the tool itself in non-production environments
- Issues already tracked via Dependabot security advisories (these are handled through the normal update workflow)
- Findings from automated scanners without a demonstrated proof of concept
- Vulnerabilities in Azure services themselves — report these to [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/report)

---

## Security Best Practices for Users

Azure Threat Lens processes sensitive security data and authenticates to Azure using privileged credentials. Follow these practices to minimise risk:

**Credential management**
- Prefer **managed identity** over client secrets wherever possible (Azure VM, App Service, AKS)
- Store secrets in `.env` locally — this file is in `.gitignore` and must never be committed
- In production, store secrets in **Azure Key Vault** and reference them via environment injection
- Rotate client secrets and threat intel API keys on a regular schedule (90 days recommended)
- Revoke and regenerate any credential that may have been exposed immediately

**Least privilege**
- Grant the service principal only the roles listed in the README (`Microsoft Sentinel Reader`, `Reader`)
- Do not assign `Owner`, `Contributor`, or `User Access Administrator` to the service principal
- Scope role assignments to the narrowest resource scope possible (workspace resource group rather than subscription where feasible)
- Review and audit service principal role assignments periodically

**Operational security**
- Use `ATL_LOG_FORMAT=json` and `ATL_LOG_LEVEL=WARNING` or higher in production to reduce log verbosity
- Do not pipe raw output containing entity details to untrusted systems
- Treat JSON investigation reports as sensitive — they may contain IP addresses, UPNs, and resource IDs
- Enable Azure AD audit logs on the service principal to detect unexpected API usage

**Network**
- Restrict outbound access to only required Azure API endpoints and threat intel provider domains if deploying behind a firewall
- Threat intel providers contacted: `www.virustotal.com`, `api.greynoise.io`, `api.abuseipdb.com`
