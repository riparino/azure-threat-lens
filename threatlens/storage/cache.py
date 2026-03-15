from __future__ import annotations

from collections.abc import MutableMapping


class InMemoryCache:
    def __init__(self) -> None:
        self._data: MutableMapping[str, object] = {}

    def get(self, key: str) -> object | None:
        return self._data.get(key)

    def set(self, key: str, value: object) -> None:
        self._data[key] = value
