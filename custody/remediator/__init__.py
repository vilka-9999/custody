"""The acting agent and the contract that bounds it."""

from custody.remediator.contract import ScopeContract, ScopeViolationError, check_scope

__all__ = ["ScopeContract", "ScopeViolationError", "check_scope"]
