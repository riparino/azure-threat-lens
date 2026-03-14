# Azure Threat Lens

Production-quality SOC investigation tool for Microsoft Sentinel and Azure security alerts.

## Features

- **Incident Triage** – risk-score and prioritise Sentinel incidents with MITRE ATT&CK mapping
- **Entity Resolution** – enrich IPs, hostnames, Azure resources, and file hashes with threat intelligence
- **Identity Investigation** – deep-dive into Entra ID sign-in anomalies, impossible travel, MFA gaps, and privileged role abuse
- **Triage Engine** – structured JSON analysis with KQL query generation; runs deterministically or with LLM reasoning
- **Azure Lighthouse** – multi-workspace support for MSSPs managing delegated Sentinel workspaces
- **AI-Assisted Analysis** – optional Claude (Anthropic) integration for natural-language incident summaries

## Integrations

| Integration | Purpose |
|---|---|
| Microsoft Sentinel API | Incident, alert, and entity retrieval |
| Microsoft Graph (Entra ID) | User profiles, sign-in logs, MFA status, role assignments |
| Azure Resource Graph | Cross-subscription resource context |
| Defender XDR | Machine alerts, advanced hunting |
| VirusTotal | IP / domain / hash threat intel |
| GreyNoise | Internet scanner classification |
| AbuseIPDB | Community IP abuse scoring |
| Anthropic Claude | LLM-powered analysis and recommendations |

## Quick Start

```bash
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your credentials
atl check-config
```

## CLI Commands

```bash
# Triage recent incidents (last 72h)
atl triage-incident --list

# Triage a specific incident
atl triage-incident INC-001-abc

# Target an Azure Lighthouse delegated workspace
atl triage-incident --list --workspace "Client A – Production"

# Resolve an entity
atl resolve-entity 198.51.100.42
atl resolve-entity malware.exe --kind FileHash

# Investigate an identity
atl investigate-identity alice@contoso.com --lookback 60

# Output as JSON (for SIEM/automation)
atl triage-incident --list -o json | jq .

# Disable LLM for offline/fast mode
atl triage-incident INC-001 --no-llm
```

## Architecture

```
src/azure_threat_lens/
├── cli/                  # Click CLI interface + Rich terminal output
├── config/               # Pydantic settings (env vars + YAML)
├── integrations/
│   ├── azure/            # Sentinel, Graph, ResourceGraph, Defender clients
│   └── threat_intel/     # VirusTotal, GreyNoise, AbuseIPDB, Enricher
├── analysis/
│   ├── triage.py         # Incident triage analyser
│   ├── triage_engine.py  # Structured triage engine (deterministic + LLM)
│   ├── entity.py         # Entity context resolver
│   └── identity.py       # Identity abuse investigator
├── llm/
│   └── reasoning.py      # Claude API integration
├── models/               # Pydantic data models
└── logging/              # Structlog setup
```

## Configuration

All settings are loaded from environment variables (or `.env`). See `.env.example` for the full reference.

Key variables:

| Variable | Description |
|---|---|
| `ATL_AZURE_TENANT_ID` | Azure AD tenant ID |
| `ATL_AZURE_CLIENT_ID` | Service principal client ID |
| `ATL_AZURE_CLIENT_SECRET` | Service principal secret |
| `ATL_SENTINEL_WORKSPACE_NAME` | Primary Sentinel workspace name |
| `ATL_SENTINEL_WORKSPACES` | JSON array of Lighthouse workspaces |
| `ATL_ANTHROPIC_API_KEY` | Anthropic API key for LLM analysis |
| `ATL_VIRUSTOTAL_API_KEY` | VirusTotal API key (optional) |

## Azure Lighthouse Support

For MSSPs managing multiple customer Sentinel workspaces, configure additional workspaces via `ATL_SENTINEL_WORKSPACES`:

```bash
export ATL_SENTINEL_WORKSPACES='[
  {
    "workspace_id": "...",
    "workspace_name": "client-a-sentinel",
    "resource_group": "rg-sentinel-a",
    "subscription_id": "...",
    "tenant_id": "...",
    "display_name": "Client A"
  }
]'
atl triage-incident --list --workspace "Client A"
```

## Triage Engine

The `TriageEngine` module provides structured JSON output suitable for automation and SOAR integration:

```python
from azure_threat_lens.analysis.triage_engine import TriageEngine, TriageEngineInput

engine = TriageEngine(use_llm=False)  # or use_llm=True for LLM-assisted mode
result = await engine.run(TriageEngineInput(
    incident=incident_dict,
    alerts=alerts_list,
    entities=entities_list,
    time_range={"start": "2024-01-15T00:00:00Z", "end": "2024-01-15T06:00:00Z"},
))
print(result.model_dump_json(indent=2))
```

Output schema:
```json
{
  "summary": "...",
  "risk_level": "high",
  "entities": [...],
  "attack_patterns": ["InitialAccess", "CredentialAccess"],
  "mitre_tactics": ["InitialAccess"],
  "mitre_techniques": ["T1078"],
  "recommended_queries": [{"name": "...", "kql": "...", ...}],
  "investigation_steps": ["1. Preserve evidence...", ...],
  "confidence": "high",
  "llm_reasoning": "..."
}
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/unit/
ruff check src/
mypy src/
```
