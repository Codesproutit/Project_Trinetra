"""Per-run token and cost accounting for the AI layer.

Pricing is USD per 1M tokens (input, output), current Anthropic API values. An
unknown model prices at 0 rather than guessing — the token counts are still
reported, so cost is never silently overstated. The router tracks tokens per
model; this turns that into a dollar figure for the run summary.
"""

from __future__ import annotations

from dataclasses import dataclass

from trinetra.providers.router import ProviderRouter

# model id -> (input $/1M, output $/1M)
_PRICING: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-5-5": (4.0, 20.0),
}


def price_of(model: str, input_tokens: int, output_tokens: int) -> float:
    in_rate, out_rate = _PRICING.get(model, (0.0, 0.0))
    return (input_tokens / 1_000_000) * in_rate + (output_tokens / 1_000_000) * out_rate


@dataclass
class CostReport:
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    priced: bool = True  # False if any used model had no price entry

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def router_cost(router: ProviderRouter) -> CostReport:
    """Price a router's accumulated per-model usage."""
    report = CostReport()
    for model, toks in router.usage.items():
        report.input_tokens += toks["input"]
        report.output_tokens += toks["output"]
        report.usd += price_of(model, toks["input"], toks["output"])
        if model not in _PRICING:
            report.priced = False
    return report
