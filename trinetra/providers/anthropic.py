"""Anthropic (Claude) provider adapter — the first concrete provider.

Uses the official `anthropic` SDK. The SDK is an optional dependency (install with
`pip install trinetra[llm]`), imported lazily so the deterministic Phase 1 scan
runs without it.
"""

from __future__ import annotations

import os

from trinetra.providers.base import Completion


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str | None = None):
        # api_key is optional here; the SDK also reads ANTHROPIC_API_KEY / a logged-in
        # profile. It is supplied by the tester at pre-flight (BYOK).
        self._api_key = api_key
        self._client = None

    def available(self) -> bool:
        """True only if the SDK is installed and a key is reachable (BYOK)."""
        try:
            import anthropic  # noqa: F401
        except ModuleNotFoundError:
            return False
        return bool(self._api_key or os.getenv("ANTHROPIC_API_KEY"))

    def _get_client(self):
        if self._client is None:
            try:
                from anthropic import Anthropic
            except ModuleNotFoundError as exc:  # pragma: no cover - optional dep
                raise RuntimeError(
                    "The 'anthropic' package is not installed. Install with "
                    "`pip install trinetra[llm]` to use the Claude provider."
                ) from exc
            self._client = Anthropic(api_key=self._api_key) if self._api_key else Anthropic()
        return self._client

    def complete(self, prompt: str, *, model: str, system: str | None = None) -> Completion:
        client = self._get_client()
        kwargs: dict = {
            "model": model,
            "max_tokens": 16000,
            "thinking": {"type": "adaptive"},  # adaptive thinking for security reasoning
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        msg = client.messages.create(**kwargs)

        if getattr(msg, "stop_reason", None) == "refusal":
            raise RuntimeError("The model declined this request (stop_reason=refusal).")

        text = "".join(
            block.text for block in msg.content if getattr(block, "type", None) == "text"
        )
        usage = getattr(msg, "usage", None)
        return Completion(
            text=text,
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
            model=model,
        )
