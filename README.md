# Azure Threat Lens

A production-quality Python CLI for Microsoft Sentinel and Azure security investigations. Azure Threat Lens automates SOC workflows by pulling data from Sentinel, Microsoft Graph, Azure Resource Graph, and Activity Logs, correlating it with external threat intelligence, and producing structured investigation reports with optional AI-assisted analysis via Azure OpenAI.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Azure App Registration Setup](#azure-app-registration-setup)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [YAML Configuration](#yaml-configuration)
  - [Multi-tenant / Azure Lighthouse](#multi-tenant--azure-lighthouse)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
  - [triage-incident](#triage-incident)
  - [resolve-entity](#resolve-entity)
  - [investigate-identity](#investigate-identity)
  - [investigate-resource](#investigate-resource)
  - [Global Flags](#global-flags)
- [Threat Intelligence Integration](#threat-intelligence-integration)
- [Azure OpenAI Integration](#azure-openai-integration)
- [Microsoft Defender XDR Integration](#microsoft-defender-xdr-integration)
- [Output Formats](#output-formats)
- [Running Tests](#running-tests)
- [Security Considerations](#security-considerations)
- [Development](#development)

---

## Features

- **Incident triage** – fetch a Sentinel incident, resolve all entities, run multi-signal analysis, and produce a prioritised investigation report with MITRE ATT&CK mapping
- **Identity investigation** – sign-in log analysis, impossible travel detection, legacy auth, MFA status, privileged role enumeration, and Defender alert correlation
- **Resource investigation** – Activity Log analysis for sensitive operations (Key Vault reads, storage key enumeration, VM run-command, RBAC changes)
- **Token & privilege analysis** – service principal credential sprawl, over-privileged app permissions, RBAC escalation detection
- **Threat intelligence enrichment** – concurrent lookup across VirusTotal, GreyNoise, and AbuseIPDB for IPs, domains, and file hashes
- **Azure OpenAI reasoning** – optional LLM-assisted narrative analysis and recommended actions (Entra ID auth, no API key required)
- **Multi-tenant support** – Azure Lighthouse workspace federation for MSSPs managing multiple tenants
- **Structured output** – rich terminal tables, JSON, or plain text for pipeline integration

---

## Architecture

```text
azure-threat-lens/
├── threatlens/
│   ├── cli/              # Click/Typer CLI entry point and command implementations
│   ├── core/             # Triage, verdict, and investigation orchestration engines
│   ├── azure/            # Azure API clients (Sentinel, Graph, Resource Graph, Activity Log)
│   ├── analysis/         # Threat analysis modules (identity, token, privilege, resource)
│   ├── entities/         # Entity resolution and enrichment (IP, hostname, UPN, ARM resource)
│   ├── intel/            # Threat intelligence providers (VirusTotal, GreyNoise, AbuseIPDB)
│   ├── models/           # Pydantic data models (incidents, entities, investigations)
│   ├── reasoning/        # Azure OpenAI LLM reasoning engine and prompt templates
│   ├── storage/          # In-memory cache and evidence persistence
│   └── utils/            # Authentication, configuration, structured logging
├── config/
│   └── default.yaml      # Default configuration values (overridden by environment variables)
└── tests/
    ├── unit/             # Unit tests for core engines and models
    └── new_unit/         # Additional unit tests
```

**Investigation pipeline:**

```
CLI command
    └─▶ InvestigationEngine.run()
            ├─▶ SentinelClient   – fetch incident + alerts
            ├─▶ EntityResolver   – resolve IP / UPN / hostname / ARM resource
            ├─▶ Analysis modules – identity, token, privilege, resource access
            ├─▶ ThreatIntelEnricher – VirusTotal / GreyNoise / AbuseIPDB
            ├─▶ TriageEngine     – score, MITRE mapping, attack hypotheses
            ├─▶ VerdictEngine    – disposition (TP/FP/…) + recommended actions
            └─▶ LLMEngine        – optional Azure OpenAI narrative (--llm flag)
```

---

## Prerequisites

| Requirement | Minimum version |
|---|---|
| Python | 3.11 |
| Azure subscription | any |
| Microsoft Sentinel workspace | any supported region |
| Azure App Registration | with the permissions listed below |

Optional:
- Azure OpenAI resource (for `--llm` enrichment)
- VirusTotal, GreyNoise, and/or AbuseIPDB API keys (for threat intel enrichment)
- Microsoft Defender XDR licence (for Defender alert correlation)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/riparino/azure-threat-lens.git
cd azure-threat-lens

# Install (production)
pip install .

# Install with development extras (linting, type checking, tests)
pip install -e ".[dev]"
```

The `threatlens` command is registered as a console script and is immediately available after install.

```bash
threatlens --help
```

---

## Azure App Registration Setup

Azure Threat Lens authenticates using a service principal (Azure App Registration). You can also use a managed identity by omitting `ATL_AZURE_CLIENT_SECRET` and relying on `DefaultAzureCredential` (see [Authentication](#authentication) below).

### 1. Create the App Registration

```bash
# Create app registration
az ad app create --display-name "azure-threat-lens"

# Create a service principal for it
az ad sp create --id <appId>

# Create a client secret (note the value – it is only shown once)
az ad app credential reset --id <appId> --append
```

Note the `appId` (client ID) and the generated secret value.

### 2. Grant Microsoft Graph API Permissions

In the Azure Portal → App registrations → your app → API permissions → Add a permission → Microsoft Graph → Application permissions:

| Permission | Purpose |
|---|---|
| `User.Read.All` | Resolve user identity, MFA status, group memberships |
| `AuditLog.Read.All` | Read sign-in logs for identity investigation |
| `Directory.Read.All` | Enumerate directory objects, roles, and service principals |
| `SecurityEvents.Read.All` | Read Defender security alerts (optional) |

Click **Grant admin consent** after adding all permissions.

### 3. Grant Azure RBAC Roles

Assign the service principal roles at the appropriate scope (subscription or resource group):

```bash
SP_OBJECT_ID=$(az ad sp show --id <appId> --query id -o tsv)
SUBSCRIPTION_ID="<your-subscription-id>"

# Required: read Sentinel incidents and workspace data
az role assignment create \
  --assignee $SP_OBJECT_ID \
  --role "Microsoft Sentinel Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Required: read Azure Activity Logs
az role assignment create \
  --assignee $SP_OBJECT_ID \
  --role "Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

**Minimum required RBAC roles:**

| Role | Scope | Purpose |
|---|---|---|
| `Microsoft Sentinel Reader` | Subscription or workspace RG | Read incidents, alerts, entities |
| `Reader` | Subscription | Activity Log, Resource Graph queries |

**Optional roles for expanded coverage:**

| Role | Purpose |
|---|---|
| `Security Reader` | Read Defender alerts and security posture data |
| `Log Analytics Reader` | Direct KQL queries against the Log Analytics workspace |

> **Principle of least privilege:** Never grant `Owner`, `Contributor`, or `User Access Administrator` to the service principal.

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

All environment variables use the `ATL_` prefix. The `.env` file is loaded automatically at startup and is listed in `.gitignore` – never commit it.

#### Required variables

| Variable | Description | Example |
|---|---|---|
| `ATL_AZURE_TENANT_ID` | Azure AD tenant ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `ATL_AZURE_CLIENT_ID` | App Registration client (application) ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `ATL_AZURE_CLIENT_SECRET` | App Registration client secret | `<secret-value>` |
| `ATL_AZURE_SUBSCRIPTION_ID` | Default Azure subscription ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `ATL_SENTINEL_WORKSPACE_ID` | Log Analytics workspace ID for Sentinel | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `ATL_SENTINEL_WORKSPACE_NAME` | Sentinel workspace name | `my-sentinel-ws` |
| `ATL_SENTINEL_RESOURCE_GROUP` | Resource group containing the workspace | `rg-security` |

#### Threat intelligence (optional)

| Variable | Description |
|---|---|
| `ATL_VIRUSTOTAL_API_KEY` | VirusTotal API key – enables IP, domain, and hash enrichment |
| `ATL_GREYNOISE_API_KEY` | GreyNoise API key – enables IP noise/scanner classification |
| `ATL_ABUSEIPDB_API_KEY` | AbuseIPDB API key – enables IP abuse score lookup |

Threat intel providers are automatically enabled when the corresponding key is set. Disabled providers are silently skipped.

#### Azure OpenAI (optional)

| Variable | Description | Example |
|---|---|---|
| `ATL_LLM_ENDPOINT` | Azure OpenAI resource endpoint | `https://myresource.openai.azure.com/` |
| `ATL_LLM_DEPLOYMENT` | Deployment name | `gpt-4o` |
| `ATL_LLM_API_VERSION` | API version (default: `2024-02-01`) | `2024-08-01-preview` |
| `ATL_LLM_MAX_TOKENS` | Maximum tokens per response (default: `4096`) | `8192` |

Authentication to Azure OpenAI uses Entra ID (the same service principal), not an API key.

#### Microsoft Defender XDR (optional)

| Variable | Default | Description |
|---|---|---|
| `ATL_DEFENDER_ENABLED` | `false` | Enable Defender alert correlation |
| `ATL_DEFENDER_TENANT_ID` | same as `ATL_AZURE_TENANT_ID` | Tenant ID if Defender is in a different tenant |

#### Output and logging

| Variable | Default | Options |
|---|---|---|
| `ATL_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `ATL_LOG_FORMAT` | `console` | `console` (human-readable), `json` (structured) |
| `ATL_OUTPUT_FORMAT` | `rich` | `rich` (coloured terminal), `json`, `plain` |

#### Other

| Variable | Default | Description |
|---|---|---|
| `ATL_CONFIG_FILE` | `config/default.yaml` | Path to the YAML configuration file |
| `ATL_CACHE_TTL_SECONDS` | `3600` | In-memory cache TTL for API responses |

### YAML Configuration

`config/default.yaml` holds defaults for all tuneable parameters. Environment variables always take precedence. You can point to a different file with `ATL_CONFIG_FILE`.

Key sections:

```yaml
sentinel:
  default_lookback_hours: 72   # how far back to query for related events
  max_incidents: 100

graph:
  signin_lookback_days: 30     # sign-in history window for identity investigations

triage:
  priority_thresholds:
    critical: 8.0
    high: 6.0
    medium: 4.0
    low: 0.0
```

### Multi-tenant / Azure Lighthouse

To query Sentinel workspaces across multiple tenants (Azure Lighthouse), set `ATL_SENTINEL_WORKSPACES` to a JSON array:

```bash
ATL_SENTINEL_WORKSPACES='[
  {
    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "workspace_name": "customer-a-sentinel",
    "resource_group": "rg-security",
    "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "display_name": "Customer A"
  },
  {
    "workspace_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "workspace_name": "customer-b-sentinel",
    "resource_group": "rg-soc",
    "subscription_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "tenant_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "display_name": "Customer B"
  }
]'
```

When this variable is set, the `-w` / `--workspace` option on `triage-incident` accepts a workspace name, ID, or display name.

### Authentication

By default the tool uses `ClientSecretCredential` (client ID + secret). If `ATL_AZURE_CLIENT_SECRET` is not set, it falls back to `DefaultAzureCredential`, which supports:

- Managed identity (recommended for Azure-hosted deployments)
- Azure CLI credentials (`az login`)
- Environment credentials
- Visual Studio Code credentials

To use a managed identity, omit `ATL_AZURE_CLIENT_SECRET` and ensure the managed identity has the same RBAC roles described above.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/riparino/azure-threat-lens.git
cd azure-threat-lens
pip install .

# 2. Configure credentials
cp .env.example .env
# Edit .env and fill in ATL_AZURE_TENANT_ID, ATL_AZURE_CLIENT_ID,
# ATL_AZURE_CLIENT_SECRET, ATL_AZURE_SUBSCRIPTION_ID,
# ATL_SENTINEL_WORKSPACE_ID, ATL_SENTINEL_WORKSPACE_NAME,
# ATL_SENTINEL_RESOURCE_GROUP

# 3. Triage a Sentinel incident
threatlens triage-incident 12345

# 4. Investigate a compromised identity
threatlens investigate-identity alice@contoso.com

# 5. Enrich an IP address with threat intelligence
threatlens resolve-entity 185.220.101.1

# 6. Investigate an Azure resource
threatlens investigate-resource /subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-kv
```

---

## CLI Commands

### triage-incident

Fetch a Sentinel incident, resolve all entities, run full multi-signal analysis, and produce a prioritised investigation report.

```
threatlens triage-incident [OPTIONS] INCIDENT_ID
```

| Argument / Option | Description |
|---|---|
| `INCIDENT_ID` | Sentinel incident number or GUID |
| `-w`, `--workspace` | Workspace name or ID (uses `ATL_SENTINEL_WORKSPACE_NAME` if omitted) |
| `--llm` / `--no-llm` | Enable Azure OpenAI narrative analysis (default: off) |

**Examples:**

```bash
# Basic triage
threatlens triage-incident 12345

# With AI-assisted analysis
threatlens triage-incident 12345 --llm

# Targeting a specific workspace (useful with Lighthouse)
threatlens triage-incident abc-1234-guid --workspace customer-a-sentinel --llm

# Output as JSON for pipeline integration
threatlens --output json triage-incident 12345
```

**Report sections:**

- **Risk Level** – `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFORMATIONAL` with a confidence score
- **Summary** – one-paragraph narrative of the incident
- **Key Entities** – table of resolved entities with per-entity risk indicators
- **Attack Hypotheses** – ranked hypotheses with MITRE ATT&CK tactic mapping
- **Verdict** – disposition (`TRUE POSITIVE`, `LIKELY TRUE POSITIVE`, `BENIGN POSITIVE`, `FALSE POSITIVE`, `UNDETERMINED`) with severity and confidence
- **Recommended Actions** – prioritised remediation steps
- **Investigation Steps** – analyst follow-up checklist
- **LLM Analysis** – extended narrative (when `--llm` is used)

### resolve-entity

Resolve and enrich a single Azure entity with threat intelligence and contextual data.

```
threatlens resolve-entity IDENTIFIER
```

| Argument | Description |
|---|---|
| `IDENTIFIER` | IP address, hostname, UPN, ARM resource ID, URL, or file hash (MD5/SHA-1/SHA-256) |

**Examples:**

```bash
# Enrich an IP address
threatlens resolve-entity 185.220.101.1

# Look up a user
threatlens resolve-entity alice@contoso.com

# Inspect an ARM resource
threatlens resolve-entity "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-kv"

# Check a file hash
threatlens resolve-entity d41d8cd98f00b204e9800998ecf8427e
```

Private/RFC-1918 IP addresses are not submitted to external threat intel providers.

### investigate-identity

Perform a deep investigation of a user identity: sign-in history, MFA status, privileged roles, impossible travel detection, legacy authentication use, and Defender alert correlation.

```
threatlens investigate-identity [OPTIONS] IDENTIFIER
```

| Argument / Option | Description |
|---|---|
| `IDENTIFIER` | UPN (`user@domain`), object ID, or account name |
| `-d`, `--days` | Lookback window in days for sign-in and audit logs (default: `7`) |

**Examples:**

```bash
# Investigate with default 7-day window
threatlens investigate-identity alice@contoso.com

# Extended 30-day lookback
threatlens investigate-identity alice@contoso.com --days 30

# Output as JSON
threatlens --output json investigate-identity alice@contoso.com --days 14
```

**Detections:**

- Impossible travel (same account, two geographically distant sign-ins within an impossible timeframe)
- Legacy authentication protocols (SMTP, IMAP, ActiveSync, POP3)
- MFA not registered or bypassed
- Assignment to high-privilege roles (Global Administrator, Privileged Role Administrator, etc.)
- Anomalous sign-in patterns (new country, new device, failed-then-succeeded sequences)
- Active Defender for Identity / Defender XDR alerts

### investigate-resource

Investigate an Azure resource for anomalous access patterns using Activity Log data.

```
threatlens investigate-resource [OPTIONS] RESOURCE_ID
```

| Argument / Option | Description |
|---|---|
| `RESOURCE_ID` | Full ARM resource ID |
| `-H`, `--hours` | Lookback window in hours for Activity Log analysis (default: `48`) |

**Examples:**

```bash
# Investigate a Key Vault over the past 48 hours
threatlens investigate-resource \
  "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-kv"

# Extended 7-day window for a storage account
threatlens investigate-resource \
  "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage" \
  --hours 168
```

**Sensitive operations flagged:**

| Operation | Description |
|---|---|
| `microsoft.keyvault/vaults/secrets/read` | Key Vault secret accessed |
| `microsoft.storage/storageaccounts/listkeys/action` | Storage account keys enumerated |
| `microsoft.compute/virtualmachines/runcommand/action` | VM run-command executed |
| `microsoft.authorization/roleassignments/write` | RBAC role assigned |
| `microsoft.authorization/roleassignments/delete` | RBAC role removed |

### Global Flags

These flags apply to all commands and can also be set via environment variables:

| Flag | Env var | Default | Options |
|---|---|---|---|
| `--log-level` | `ATL_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--log-format` | `ATL_LOG_FORMAT` | `console` | `console`, `json` |
| `-o`, `--output` | `ATL_OUTPUT_FORMAT` | `rich` | `rich`, `json`, `plain` |
| `--version` | – | – | Print version and exit |
| `-h`, `--help` | – | – | Show help |

**Examples:**

```bash
# Debug logging
threatlens --log-level DEBUG triage-incident 12345

# JSON output for SIEM ingestion
threatlens --output json --log-format json triage-incident 12345

# Plain output (no ANSI codes)
threatlens --output plain triage-incident 12345
```

---

## Threat Intelligence Integration

Set any combination of the following keys in your `.env` to enable enrichment:

```bash
ATL_VIRUSTOTAL_API_KEY=<key>
ATL_GREYNOISE_API_KEY=<key>
ATL_ABUSEIPDB_API_KEY=<key>
```

Enrichment runs concurrently across all configured providers. Results are combined into a weighted risk score. Private IP addresses (RFC-1918, loopback, link-local) are never submitted to external providers.

| Provider | Enriches | Signal |
|---|---|---|
| VirusTotal | IPs, domains, file hashes | Malware detections, community score |
| GreyNoise | IPs | Known scanner / benign noise classification, malicious intent |
| AbuseIPDB | IPs | Community-reported abuse confidence score |

---

## Azure OpenAI Integration

Add the following to your `.env` to enable AI-assisted narrative analysis:

```bash
ATL_LLM_ENDPOINT=https://<resource-name>.openai.azure.com/
ATL_LLM_DEPLOYMENT=gpt-4o
ATL_LLM_API_VERSION=2024-02-01   # optional, a default is provided
```

Authentication is handled via the same Entra ID service principal — no OpenAI API key is needed. Ensure the service principal has the **Cognitive Services OpenAI User** role on the Azure OpenAI resource:

```bash
az role assignment create \
  --assignee $SP_OBJECT_ID \
  --role "Cognitive Services OpenAI User" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<resource-name>"
```

Enable LLM analysis at invocation time with `--llm`:

```bash
threatlens triage-incident 12345 --llm
```

The LLM is provided with all structured evidence gathered during the investigation and returns a concise narrative with recommended actions. It is never used as the primary signal source — the deterministic triage and verdict engines always run first.

---

## Microsoft Defender XDR Integration

```bash
ATL_DEFENDER_ENABLED=true
# Only needed if Defender is in a different tenant than ATL_AZURE_TENANT_ID:
ATL_DEFENDER_TENANT_ID=<tenant-id>
```

When enabled, Defender alerts are correlated with identity and resource investigations to improve verdict confidence. The service principal requires the **Security Reader** role in the Defender tenant.

---

## Output Formats

### rich (default)

Coloured terminal output with tables, panels, and rule separators. Best for interactive use.

### json

Machine-readable JSON written to stdout. Use this for SIEM ingestion, scripting, or storing investigation reports:

```bash
threatlens --output json triage-incident 12345 | jq '.verdict.disposition'
```

### plain

Compact JSON without ANSI codes. Suitable for piping to tools that do not handle ANSI escape sequences.

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all unit tests
pytest tests/ -q

# Run with verbose output
pytest tests/ -v

# Run a specific test file
pytest tests/unit/test_triage_engine.py -v

# Run with coverage
pytest tests/ --cov=threatlens --cov-report=term-missing

# Lint and type-check
ruff check threatlens/
mypy threatlens/
```

Integration tests require real Azure credentials and are tagged accordingly. Unit tests run fully offline using mocked API responses.

---

## Security Considerations

### Credential management

- Store all secrets in `.env` (never commit this file — it is in `.gitignore`)
- In production, prefer **Azure Key Vault** or **managed identity** over client secrets
- Rotate client secrets and threat intel API keys periodically
- Revoke credentials immediately if a secret is accidentally exposed

### Service principal permissions

- Follow the principle of least privilege: grant only the roles listed in [Azure App Registration Setup](#azure-app-registration-setup)
- Avoid subscription-level `Contributor` or `Owner` for the service principal
- Enable Azure AD audit logs on the service principal to detect unexpected usage

### Managed identity (recommended for Azure-hosted deployments)

When running on an Azure VM, App Service, Container Instance, or AKS pod, use a managed identity instead of a client secret. Set the managed identity's RBAC roles as described above, and omit `ATL_AZURE_CLIENT_SECRET` from the environment. `DefaultAzureCredential` will automatically use the managed identity.

### Network security

- Restrict outbound access to only the required Azure API endpoints if deploying behind a firewall
- Threat intel API calls go to `virustotal.com`, `api.greynoise.io`, and `api.abuseipdb.com` — whitelist these if needed

### Logging

- Use `ATL_LOG_FORMAT=json` in production for structured log ingestion
- Secrets are stored as `SecretStr` and are never written to logs
- Set `ATL_LOG_LEVEL=WARNING` or higher in production to reduce log volume

---

## Development

### Project structure

```text
threatlens/          # Main package
tests/               # pytest test suite
config/              # YAML defaults
.env.example         # Environment variable template
pyproject.toml       # Build metadata, dependencies, tool config
```

### Adding a new analysis module

1. Create `threatlens/analysis/my_analysis.py` with an `async def analyse(...)` function
2. Register it in `threatlens/core/investigation_engine.py` inside `InvestigationConfig`
3. Add corresponding unit tests in `tests/unit/`

### Adding a new threat intel provider

1. Implement the provider in `threatlens/intel/my_provider.py` following the existing `VirusTotalClient` interface
2. Register it in `threatlens/intel/enricher.py`
3. Add the API key to `.env.example` and `threatlens/utils/config.py`

### Code style

```bash
# Auto-fix linting issues
ruff check --fix threatlens/

# Type checking
mypy threatlens/
```

The project targets Python 3.11 with strict mypy and ruff linting (`E`, `F`, `I`, `UP`, `B`, `SIM` rule sets).

---

## License

MIT License. See [LICENSE](LICENSE) for details.
