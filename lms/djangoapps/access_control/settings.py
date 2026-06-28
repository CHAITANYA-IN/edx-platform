"""Settings helpers for LMS external access control."""

import os

from django.conf import settings

FEATURES = getattr(settings, "FEATURES", {})
DEFAULT_PUBLIC_KEY_PATH = os.path.join(
    os.path.dirname(__file__),
    "keys",
    "public_key.pem",
)

USE_EXTERNAL_ACCESS_CONTROL = FEATURES.get("ENABLE_EXTERNAL_ACCESS_CONTROL", False)
AC_URL = getattr(settings, "EXTERNAL_ACCESS_CONTROL_URL", "http://127.0.0.1:10000/access")
AC_REQUEST_TIMEOUT = getattr(settings, "EXTERNAL_ACCESS_CONTROL_REQUEST_TIMEOUT", 20)
AC_PUBLIC_KEY_PATH = getattr(
    settings,
    "EXTERNAL_ACCESS_CONTROL_PUBLIC_KEY_PATH",
    DEFAULT_PUBLIC_KEY_PATH,
)
AC_CAPABILITIES_RESPONSE_KEY = getattr(
    settings,
    "EXTERNAL_ACCESS_CONTROL_RESPONSE_KEY",
    "access_control_vars",
)
AC_LOG_PREFIX = getattr(
    settings,
    "EXTERNAL_ACCESS_CONTROL_LOG_PREFIX",
    "[external_access_control]",
)
