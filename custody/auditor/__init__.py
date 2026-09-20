"""Independent adjudication of remediation claims.

The auditor never reads the remediator's prose. It re-derives what happened
from artifacts: the diff, the test results, and a fresh deterministic survey.
"""

from custody.auditor.detectors import Detection, DiffContext, run_detectors

__all__ = ["Detection", "DiffContext", "run_detectors"]
