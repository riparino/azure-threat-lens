# Azure Threat Lens

Azure Threat Lens is a production-quality Python security investigation tool for Microsoft Sentinel and Azure environments.

## Goals

- Modular architecture with clear separation between CLI, investigation logic, Azure integrations, threat intel, and reasoning.
- Scalable investigation patterns that work across many subscriptions and thousands of resources.
- Generic Azure resource handling through Azure Resource Graph.
- Extensible module system for adding new investigation workflows without changing core routing code.

## Repository structure

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
│   │   └── abuseipdb_client.py
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

## CLI commands

```bash
threatlens triage-incident <incident-id>
threatlens resolve-entity <entity>
threatlens investigate-identity <identity>
threatlens investigate-resource <resource-id>
```

Each command follows the same pipeline:

1. Collect Azure data
2. Resolve entities
3. Perform analysis
4. Output a structured investigation report (JSON)

## Development

```bash
pip install -e ".[dev]"
pytest tests/new_unit -q
```
