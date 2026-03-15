"""In-memory and disk-based cache for threat intelligence lookups and Azure API responses.

Two cache tiers:
  - L1: In-process TTL dict (fastest, lost on restart)
  - L2: SQLite on-disk cache (persists across restarts, configurable path)

Usage::

    cache = ThreatLensCache()
    await cache.set("vt:1.2.3.4", result, ttl=3600)
    hit = await cache.get("vt:1.2.3.4")
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".threatlens" / "cache.db"
_DEFAULT_TTL = 3600  # 1 hour


class _L1Cache:
    """Simple in-memory TTL cache."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}  # key → (value, expires_at)
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int) -> None:
        async with self._lock:
            self._store[key] = (value, time.time() + ttl)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    async def evict_expired(self) -> int:
        now = time.time()
        async with self._lock:
            expired = [k for k, (_, exp) in self._store.items() if now > exp]
            for k in expired:
                del self._store[k]
        return len(expired)


class _L2Cache:
    """SQLite-backed persistent cache."""

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._conn: sqlite3.Connection | None = None

    def _open(self) -> sqlite3.Connection:
        if self._conn is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._path), check_same_thread=False)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache (expires_at)")
            conn.commit()
            self._conn = conn
        return self._conn

    def get(self, key: str) -> Any | None:
        try:
            conn = self._open()
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            value_json, expires_at = row
            if time.time() > expires_at:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
                return None
            return json.loads(value_json)
        except Exception as exc:
            log.warning("cache.l2.get.failed", key=key, error=str(exc))
            return None

    def set(self, key: str, value: Any, ttl: int) -> None:
        try:
            conn = self._open()
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(value, default=str), time.time() + ttl),
            )
            conn.commit()
        except Exception as exc:
            log.warning("cache.l2.set.failed", key=key, error=str(exc))

    def delete(self, key: str) -> None:
        try:
            conn = self._open()
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
        except Exception as exc:
            log.warning("cache.l2.delete.failed", key=key, error=str(exc))

    def evict_expired(self) -> int:
        try:
            conn = self._open()
            cursor = conn.execute(
                "DELETE FROM cache WHERE expires_at < ?", (time.time(),)
            )
            conn.commit()
            return cursor.rowcount
        except Exception as exc:
            log.warning("cache.l2.evict.failed", error=str(exc))
            return 0

    def stats(self) -> dict[str, Any]:
        try:
            conn = self._open()
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at < ?", (time.time(),)
            ).fetchone()[0]
            return {"total_entries": total, "expired_entries": expired}
        except Exception as exc:
            log.warning("cache.l2.stats.failed", error=str(exc))
            return {}


class ThreatLensCache:
    """Two-tier cache: L1 (in-memory) → L2 (SQLite).

    Keys follow the convention: ``<provider>:<identifier>``
    e.g. ``vt:1.2.3.4``, ``gn:evil.example.com``, ``rg:/subscriptions/…``
    """

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        default_ttl: int = _DEFAULT_TTL,
        l2_enabled: bool = True,
    ) -> None:
        self._ttl = default_ttl
        self._l1 = _L1Cache()
        self._l2 = _L2Cache(db_path or _DEFAULT_DB_PATH) if l2_enabled else None

    async def get(self, key: str) -> Any | None:
        # L1 first
        value = await self._l1.get(key)
        if value is not None:
            return value
        # L2 fallback
        if self._l2:
            value = await asyncio.get_event_loop().run_in_executor(None, self._l2.get, key)
            if value is not None:
                # Promote to L1
                await self._l1.set(key, value, self._ttl)
                return value
        return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        effective_ttl = ttl if ttl is not None else self._ttl
        await self._l1.set(key, value, effective_ttl)
        if self._l2:
            await asyncio.get_event_loop().run_in_executor(
                None, self._l2.set, key, value, effective_ttl
            )

    async def delete(self, key: str) -> None:
        await self._l1.delete(key)
        if self._l2:
            await asyncio.get_event_loop().run_in_executor(None, self._l2.delete, key)

    async def get_or_set(
        self,
        key: str,
        loader: Any,
        ttl: int | None = None,
    ) -> Any:
        """Return cached value or call ``loader()`` to populate it."""
        hit = await self.get(key)
        if hit is not None:
            log.debug("cache.hit", key=key)
            return hit
        log.debug("cache.miss", key=key)
        value = await loader()
        await self.set(key, value, ttl)
        return value

    async def evict_expired(self) -> dict[str, int]:
        l1_count = await self._l1.evict_expired()
        l2_count = 0
        if self._l2:
            l2_count = await asyncio.get_event_loop().run_in_executor(
                None, self._l2.evict_expired
            )
        return {"l1_evicted": l1_count, "l2_evicted": l2_count}

    def stats(self) -> dict[str, Any]:
        l2_stats = self._l2.stats() if self._l2 else {}
        return {"l2": l2_stats}


# ── Module-level singleton ─────────────────────────────────────────────────────

_cache_instance: ThreatLensCache | None = None


def get_cache() -> ThreatLensCache:
    """Return the module-level singleton cache instance."""
    global _cache_instance
    if _cache_instance is None:
        from threatlens.utils.config import get_settings
        cfg = get_settings()
        _cache_instance = ThreatLensCache(
            default_ttl=cfg.cache_ttl_seconds if hasattr(cfg, "cache_ttl_seconds") else _DEFAULT_TTL
        )
    return _cache_instance
