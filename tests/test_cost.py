"""Tests for per-run cost accounting."""

from trinetra.providers.base import Completion
from trinetra.providers.router import ProviderRouter, Tier
from trinetra.telemetry.cost import price_of, router_cost


def test_price_of_known_model():
    # 1M input @ $2 + 1M output @ $10 = $12 for claude-sonnet-5.
    assert price_of("claude-sonnet-5", 1_000_000, 1_000_000) == 12.0


def test_price_of_unknown_model_is_zero_but_tokens_kept():
    assert price_of("mystery-model", 1_000_000, 1_000_000) == 0.0


class _P:
    name = "p"

    def complete(self, prompt, *, model, system=None):
        return Completion(text="{}", input_tokens=500_000, output_tokens=100_000, model=model)


def test_router_cost_sums_per_model_usage():
    router = ProviderRouter(_P())
    router.run("x", tier=Tier.REVIEW)  # claude-sonnet-5: 0.5M in, 0.1M out
    report = router_cost(router)
    # 0.5M*$2 + 0.1M*$10 = $1.0 + $1.0 = $2.0
    assert report.usd == 2.0
    assert report.input_tokens == 500_000
    assert report.output_tokens == 100_000
    assert report.priced is True


def test_router_cost_flags_unpriced_model():
    router = ProviderRouter(_P())
    router.usage["mystery"] = {"input": 10, "output": 10}
    report = router_cost(router)
    assert report.priced is False
