from __future__ import annotations


class LLMEngine:
    def summarize(self, text: str) -> str:
        return f"Deterministic summary: {text[:160]}"
