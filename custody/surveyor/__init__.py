"""Deterministic repository analysis.

Nothing in this package calls a language model. Given the same repository
contents, the surveyor emits the same findings in the same order, which is
what lets the auditor re-run it later and compare results honestly.
"""

from custody.surveyor.ast_rules import survey_source
from custody.surveyor.secrets import survey_secrets

__all__ = ["survey_source", "survey_secrets"]
