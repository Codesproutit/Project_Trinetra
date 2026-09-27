"""BYOK provider layer — one interface, many vendors.

The Anthropic adapter is the first concrete implementation. OpenAI, Gemini, and
local OpenAI-compatible endpoints implement the same LLMProvider protocol. The AI
cognitive pass (a later phase) is the first caller; nothing here runs during a
Phase 1 scan.
"""

from trinetra.providers.base import Completion, LLMProvider
from trinetra.providers.router import ProviderRouter

__all__ = ["Completion", "LLMProvider", "ProviderRouter"]
