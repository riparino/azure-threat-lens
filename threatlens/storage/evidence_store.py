from __future__ import annotations

from pathlib import Path


class EvidenceStore:
    def __init__(self, base_dir: str = ".evidence") -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    def persist(self, key: str, content: str) -> Path:
        file_path = self._base / f"{key}.json"
        file_path.write_text(content, encoding="utf-8")
        return file_path
