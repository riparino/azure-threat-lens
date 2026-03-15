from __future__ import annotations


class LLMEngine:
    async def summarize(self, prompt: str, context: dict[str, object]) -> str:
        _ = context
        return f"LLM summary placeholder: {prompt}"
