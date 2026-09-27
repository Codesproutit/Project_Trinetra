"""AI cognitive layer: strict dedup gate + LLM reviewer."""

from trinetra.ai.dedup import needs_review
from trinetra.ai.reviewer import AiReviewer, ReviewOutcome, Verdict, parse_verdict

__all__ = ["needs_review", "AiReviewer", "ReviewOutcome", "Verdict", "parse_verdict"]
