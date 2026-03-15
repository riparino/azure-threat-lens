# Azure Threat Lens

Azure Threat Lens is a production-focused Python investigation framework for Microsoft Sentinel and Azure security operations. It is designed for environments with many subscriptions and thousands of resources by treating cloud assets generically through Azure Resource Graph.

## Core Capabilities

- Incident triage assistant
- Entity resolution
- Identity abuse investigation
- Azure resource investigation
- Threat intelligence enrichment
- Structured investigation output

## Architecture

```text
azure-threat-lens/
├── README.md
├── LICENSE
├── pyproject.toml
├── .env.example
├── threatlens/
│   ├── cli/
│   │   ├── main.py
│   │   └── commands.py
│   ├── core/
│   │   ├── triage_engine.py
│   │   ├── verdict_engine.py
│   │   └── investigation_engine.py
│   ├── entities/
│   │   ├── entity_resolver.py
│   │   ├── azure_resource_resolver.py
│   │   ├── identity_resolver.py
│   │   └── network_resolver.py
│   ├── azure/
│   │   ├── sentinel_client.py
│   │   ├── graph_client.py
│   │   ├── resource_graph_client.py
│   │   └── activity_log_client.py
│   ├── analysis/
│   │   ├── identity_abuse.py
│   │   ├── token_abuse.py
│   │   ├── privilege_escalation.py
│   │   └── resource_access_analysis.py
│   ├── intel/
│   │   ├── virustotal_client.py
│   │   ├── greynoise_client.py
│   │   ├── abuseipdb_client.py
│   │   └── enricher.py
│   ├── models/
│   │   ├── entities.py
│   │   ├── incidents.py
│   │   └── investigations.py
│   ├── reasoning/
│   │   ├── llm_engine.py
│   │   └── prompt_templates.py
│   ├── storage/
│   │   ├── cache.py
│   │   └── evidence_store.py
│   └── utils/
│       ├── auth.py
│       ├── logging.py
│       └── config.py
└── tests/
```

The `InvestigationEngine` uses a module registry pattern so new investigation modules can be registered and executed without editing existing core orchestration.

## CLI Usage

```bash
threatlens triage-incident <incident-id>
threatlens resolve-entity <entity>
threatlens investigate-identity <identity>
threatlens investigate-resource <resource-id>
```

Each command executes a standard pipeline:
1. Collect Azure data
2. Resolve entities
3. Perform analysis
4. Output a structured JSON investigation report

## Local setup

```bash
pip install -e ".[dev]"
threatlens --help
pytest -q
```
