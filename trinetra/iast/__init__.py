"""Interactive AST — the bridge that fuses static sinks with dynamic proof."""

from trinetra.iast.bridge import (
    CorrelationResult,
    VerificationTask,
    correlate,
    derive_tasks,
    mint_oast_callbacks,
    vuln_class,
)

__all__ = [
    "CorrelationResult",
    "VerificationTask",
    "correlate",
    "derive_tasks",
    "mint_oast_callbacks",
    "vuln_class",
]
