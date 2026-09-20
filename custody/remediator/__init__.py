"""The acting agent and the contract that bounds it."""

from custody.remediator.contract import ScopeContract, ScopeViolation, check_scope

__all__ = ["ScopeContract", "ScopeViolation", "check_scope"]
