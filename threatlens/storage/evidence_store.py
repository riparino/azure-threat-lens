"""Evidence store – persists investigation reports and evidence to disk.

Reports are stored as newline-delimited JSON in::

    ~/.threatlens/investigations/<incident_id>/<timestamp>.json

This allows incremental evidence accumulation and later review.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_DEFAULT_STORE_PATH = Path.home() / ".threatlens" / "investigations"


class EvidenceRecord(BaseModel):
    incident_id: str
    record_type: str  # e.g. "triage", "verdict", "entity", "raw_event"
    source: str       # e.g. "sentinel", "graph", "virustotal"
    data: dict[str, Any]
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_jsonl(self) -> str:
        return self.model_dump_json()


class EvidenceStore:
    """Append-only store for investigation evidence records."""

    def __init__(self, base_path: Path | None = None) -> None:
        self._base = base_path or _DEFAULT_STORE_PATH

    def _incident_dir(self, incident_id: str) -> Path:
        # Sanitise incident_id for use as a directory name
        safe_id = incident_id.replace("/", "_").replace("\\", "_")[:80]
        return self._base / safe_id

    def _latest_path(self, incident_id: str) -> Path:
        return self._incident_dir(incident_id) / "evidence.jsonl"

    def append(self, record: EvidenceRecord) -> None:
        """Append an evidence record to the incident's JSONL file."""
        path = self._latest_path(record.incident_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(record.to_jsonl() + "\n")
            log.debug(
                "evidence_store.append",
                incident_id=record.incident_id,
                record_type=record.record_type,
            )
        except OSError as exc:
            log.error("evidence_store.append.failed", error=str(exc))

    def save_report(self, incident_id: str, report: dict[str, Any]) -> Path:
        """Save a complete investigation report as a timestamped JSON file."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self._incident_dir(incident_id) / f"report_{ts}.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            log.info("evidence_store.report_saved", path=str(path))
        except OSError as exc:
            log.error("evidence_store.save_report.failed", error=str(exc))
        return path

    def load_report(self, incident_id: str, *, latest: bool = True) -> dict[str, Any] | None:
        """Load a saved investigation report from disk."""
        inc_dir = self._incident_dir(incident_id)
        if not inc_dir.exists():
            return None
        reports = sorted(inc_dir.glob("report_*.json"), reverse=latest)
        if not reports:
            return None
        try:
            return json.loads(reports[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("evidence_store.load_report.failed", error=str(exc))
            return None

    def load_evidence(self, incident_id: str) -> list[EvidenceRecord]:
        """Load all evidence records for an incident from the JSONL file."""
        path = self._latest_path(incident_id)
        if not path.exists():
            return []
        records: list[EvidenceRecord] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(EvidenceRecord.model_validate_json(line))
                    except Exception as exc:
                        log.warning("evidence_store.parse_line.failed", error=str(exc))
        except OSError as exc:
            log.error("evidence_store.load_evidence.failed", error=str(exc))
        return records

    def list_incidents(self) -> list[str]:
        """Return a list of incident IDs that have stored evidence."""
        if not self._base.exists():
            return []
        return [d.name for d in sorted(self._base.iterdir()) if d.is_dir()]

    def incident_summary(self, incident_id: str) -> dict[str, Any]:
        """Return a brief summary of stored evidence for an incident."""
        inc_dir = self._incident_dir(incident_id)
        reports = sorted(inc_dir.glob("report_*.json")) if inc_dir.exists() else []
        evidence_path = self._latest_path(incident_id)
        record_count = 0
        if evidence_path.exists():
            try:
                record_count = sum(
                    1 for line in evidence_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                )
            except OSError:
                pass
        return {
            "incident_id": incident_id,
            "report_count": len(reports),
            "evidence_records": record_count,
            "latest_report": reports[-1].name if reports else None,
        }

    def delete_incident(self, incident_id: str) -> bool:
        """Delete all stored data for an incident. Returns True if anything was deleted."""
        import shutil
        inc_dir = self._incident_dir(incident_id)
        if not inc_dir.exists():
            return False
        try:
            shutil.rmtree(inc_dir)
            log.info("evidence_store.deleted", incident_id=incident_id)
            return True
        except OSError as exc:
            log.error("evidence_store.delete.failed", error=str(exc))
            return False


# ── Module-level singleton ─────────────────────────────────────────────────────

_store_instance: EvidenceStore | None = None


def get_evidence_store() -> EvidenceStore:
    """Return the module-level singleton evidence store."""
    global _store_instance
    if _store_instance is None:
        _store_instance = EvidenceStore()
    return _store_instance
