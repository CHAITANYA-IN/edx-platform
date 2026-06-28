"""Exceptions and denial helpers for LMS external access control."""

from lms.djangoapps.teams.errors import AddToIncompatibleTeamError, AlreadyOnTeamInTeamset, NotEnrolledInCourseForTeam


class UnsupportedAssertionError(Exception):
    """Raised when an access-control constraint cannot be translated safely."""


class AssertionValidationError(Exception):
    """Raised when a request payload or queryset violates access-control constraints."""

    def __init__(self, detail):
        super().__init__(str(detail))
        self.detail = detail


class PolicyDecisionDenied(Exception):
    """Raised when policy denies a request with a reason code and status."""

    def __init__(self, capability_name, reason_code, status_code=403, mapped_error=None):
        self.capability_name = capability_name
        self.reason_code = reason_code
        self.status_code = int(status_code or 403)
        self.mapped_error = mapped_error
        super().__init__(f"{capability_name} denied: {reason_code} ({self.status_code})")


DENY_REASON_TO_ERROR = {
    ("submit_team_membership_api", "not-enrolled-in-course"): NotEnrolledInCourseForTeam,
    ("submit_team_membership_api", "already-on-team-in-teamset"): AlreadyOnTeamInTeamset,
    ("submit_team_membership_api", "incompatible-team-protection"): AddToIncompatibleTeamError,
}


def get_denial_exception(capability_name, deny_reason):
    """Return the mapped Open edX exception instance for a policy deny reason, if any."""
    error_class = DENY_REASON_TO_ERROR.get((capability_name, deny_reason))
    if error_class is None:
        return None
    return error_class()


def build_policy_decision_denied(capability_name, capability):
    """Build a status-aware denial exception from a capability result."""
    if not capability or capability.get("decision", False):
        return None

    reason_code = capability.get("deny_reason") or "access-denied"
    status_code = capability.get("deny_status_code") or 403
    mapped_error = get_denial_exception(capability_name, reason_code)
    return PolicyDecisionDenied(capability_name, reason_code, status_code, mapped_error=mapped_error)
