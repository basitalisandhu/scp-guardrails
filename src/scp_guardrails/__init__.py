"""scp-guardrails: an AWS service control policy builder and linter.

Builds AWS Organizations service control policies (SCPs) from a short spec, lints existing SCPs for the
mistakes that lock you out or do nothing, diffs two SCPs by statement and action set, and explains a policy in
plain English. Standard library only; it never calls AWS.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
