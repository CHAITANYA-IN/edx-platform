"""Route-to-capability map for LMS external access control."""

CAPABILITY_MAP = {
    # ("GET", "/api/course_home/v1/dates/<course_id>"): ["view_dates_api"],
    # ("GET", "/api/grades/v1/gradebook/<course_id>/grading-info"): ["view_grading_info_api"],
    # (
    #     "POST",
    #     "/api/xblock/v2/xblocks/<usage_key>/handler/<user_token>/<handler_name>/<suffix>",
    # ): ["submit_xblock_handler_api"],
    ("POST", "/api/team/v0/team_membership"): ["submit_team_membership_api"],
}
