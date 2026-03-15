from __future__ import annotations


class NetworkResolver:
    def resolve(self, observable: str) -> dict[str, str]:
        kind = "ip" if observable.replace('.', '').isdigit() else "domain"
        return {"observable": observable, "kind": kind}
