"""Request-scoped external access control middleware for LMS APIs."""

from __future__ import annotations

import binascii
import contextvars
import json
import logging
from collections.abc import Mapping
from functools import lru_cache
from types import MappingProxyType
from urllib.parse import parse_qsl, urlsplit

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext_noop
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser
from openedx.core.lib.api.authentication import BearerAuthenticationAllowInactiveUser
from openedx.core.lib.api.view_utils import build_api_error

from lms.djangoapps.access_control.mappings import CAPABILITY_MAP
from lms.djangoapps.access_control.errors import PolicyDecisionDenied
from lms.djangoapps.access_control.assertions import apply_assertions_to_queryset, constraints_to_assertions
from lms.djangoapps.access_control.settings import (
    AC_CAPABILITIES_RESPONSE_KEY,
    AC_LOG_PREFIX,
    AC_PUBLIC_KEY_PATH,
    AC_REQUEST_TIMEOUT,
    AC_URL,
    USE_EXTERNAL_ACCESS_CONTROL,
)

logger = logging.getLogger(__name__)


class AccessHandle:
    """Immutable access-control server response scoped to a request."""

    __slots__ = (
        "_capabilities",
        "_params",
        "_context",
        "_warnings",
        "_errors",
        "_signed_hash",
        "_timestamp",
    )

    __ctx = contextvars.ContextVar("lms_access_handle_ctx", default=None)

    @classmethod
    def current(cls):
        handle = cls.__ctx.get()
        if handle is None:
            handle = cls()
            cls.__ctx.set(handle)
            logger.info("%s AccessHandle.current created new handle", AC_LOG_PREFIX)
        return handle

    @classmethod
    def get_current(cls):
        return cls.__ctx.get()

    @classmethod
    def clear(cls):
        handle = cls.__ctx.get()
        if handle:
            handle.reset_for_new_request()
            logger.info("%s AccessHandle.clear reset existing handle", AC_LOG_PREFIX)
        cls.__ctx.set(None)

    @staticmethod
    def freeze_json(value):
        if isinstance(value, dict):
            return MappingProxyType({
                key: AccessHandle.freeze_json(item)
                for key, item in value.items()
            })
        if isinstance(value, list):
            return tuple(AccessHandle.freeze_json(item) for item in value)
        return value

    @staticmethod
    def thaw_json(value):
        if isinstance(value, MappingProxyType):
            return {
                key: AccessHandle.thaw_json(item)
                for key, item in value.items()
            }
        if isinstance(value, tuple):
            return [AccessHandle.thaw_json(item) for item in value]
        return value

    def __setattr__(self, key, value):
        if key in self.__slots__ and hasattr(self, key):
            raise AttributeError(f"{self.__class__.__name__} attribute '{key}' is immutable")
        super().__setattr__(key, value)

    @property
    def capabilities(self):
        return getattr(self, "_capabilities", MappingProxyType({}))

    @property
    def params(self):
        return getattr(self, "_params", MappingProxyType({}))

    @property
    def context(self):
        return getattr(self, "_context", MappingProxyType({}))

    @property
    def signed_hash(self):
        return getattr(self, "_signed_hash", None)

    @property
    def timestamp(self):
        return getattr(self, "_timestamp", None)

    @property
    def warnings(self):
        return getattr(self, "_warnings", [])

    @property
    def errors(self):
        return getattr(self, "_errors", [])

    @staticmethod
    def validate_server_response(response_data):
        if not isinstance(response_data, dict):
            raise ValueError("Access-control response must be a JSON object")
        for key in ("timestamp", "capabilities", "params", "context", "signed_hash"):
            if key not in response_data:
                raise ValueError(f"Access-control response is missing {key}")
        return response_data

    def store_server_response(
        self,
        capabilities,
        params,
        context,
        warnings,
        errors,
        signed_hash,
        timestamp,
    ):
        self._capabilities = self.freeze_json(capabilities or {})
        self._params = MappingProxyType(params or {})
        self._context = MappingProxyType(context or {})
        self._warnings = warnings or []
        self._errors = errors or []
        self._signed_hash = signed_hash
        self._timestamp = timestamp
        logger.info(
            "%s AccessHandle.store_server_response capabilities=%s warnings=%d errors=%d timestamp=%s",
            AC_LOG_PREFIX,
            sorted((capabilities or {}).keys()),
            len(self._warnings),
            len(self._errors),
            self._timestamp,
        )

    def reset_for_new_request(self):
        for attr in self.__slots__:
            if hasattr(self, attr):
                super().__delattr__(attr)

    def has_server_response(self):
        return hasattr(self, "_capabilities") and hasattr(self, "_signed_hash") and hasattr(self, "_timestamp")

    def route_matches(self, route_template, request_uri):
        route = urlsplit(route_template)
        request = urlsplit(request_uri or "")
        route_parts = [part for part in route.path.strip("/").split("/") if part]
        path_parts = [part for part in request.path.strip("/").split("/") if part]
        if len(route_parts) != len(path_parts):
            return False
        for route_part, path_part in zip(route_parts, path_parts):
            if route_part.startswith("<") and route_part.endswith(">"):
                continue
            if route_part != path_part:
                return False
        route_query = dict(parse_qsl(route.query, keep_blank_values=True))
        request_query = dict(parse_qsl(request.query, keep_blank_values=True))
        for key, value in route_query.items():
            if request_query.get(key) != value:
                return False
        return True

    def capabilities_for_request(self):
        request_method = self.params.get("request_method")
        request_uri = self.params.get("request_uri")
        capabilities = {
            capability_name: self.capabilities.get(capability_name)
            for (method, route_template), capability_names in CAPABILITY_MAP.items()
            if method == request_method and self.route_matches(route_template, request_uri)
            for capability_name in capability_names
        }
        logger.info(
            "%s AccessHandle.capabilities_for_request method=%s uri=%s capabilities=%s",
            AC_LOG_PREFIX,
            request_method,
            request_uri,
            sorted(capabilities.keys()),
        )
        return MappingProxyType(capabilities)

    def capability_decisions(self):
        return {
            capability_name: bool(capability.get("decision", False))
            for capability_name, capability in self.capabilities.items()
            if isinstance(capability, Mapping)
        }

    def capability_result(self, capability_name):
        capability = self.capabilities.get(capability_name)
        if isinstance(capability, Mapping):
            return capability
        return None

    def assert_capability_decisions(self, capabilities=None):
        selected_capabilities = capabilities or self.capabilities_for_request()
        failed = []
        for capability_name, capability in selected_capabilities.items():
            if not capability or not capability.get("decision", False):
                failed.append(capability_name)
        if failed:
            logger.warning(
                "%s AccessHandle.assert_capability_decisions denied capabilities=%s",
                AC_LOG_PREFIX,
                failed,
            )
            raise PermissionError(f"Access-control capability decision denied: {', '.join(failed)}")
        logger.info(
            "%s AccessHandle.assert_capability_decisions allowed capabilities=%s",
            AC_LOG_PREFIX,
            sorted(selected_capabilities.keys()),
        )
        return True

    def matching_constraints(self, capability_names=None, resource=None, action=None):
        selected = []
        if capability_names:
            capabilities = {
                capability_name: self.capabilities.get(capability_name)
                for capability_name in capability_names
            }
        else:
            capabilities = self.capabilities_for_request()
        for result in capabilities.values():
            if not result:
                continue
            for constraint in result.get("constraints") or []:
                if resource and constraint.get("resource") != resource:
                    continue
                if action and constraint.get("action") != action:
                    continue
                selected.append(constraint)
        return selected

    def filter_queryset(
        self,
        queryset,
        policy_name=None,
        capability_names=None,
        strict=True,
        action="read",
        constraint_key="query_constraints",
    ):
        selected_capability_names = capability_names or (
            (policy_name,) if policy_name else self.capabilities_for_request().keys()
        )
        constraints = self.matching_constraints(
            capability_names=selected_capability_names,
            resource=getattr(getattr(queryset, "model", None), "__name__", None),
            action=action,
        )
        filtered_queryset = apply_assertions_to_queryset(
            queryset,
            constraints_to_assertions(constraints, constraint_key, context=self.context),
            strict=strict,
        )
        logger.info(
            "%s AccessHandle.filter_queryset model=%s action=%s constraint_key=%s constraints=%d",
            AC_LOG_PREFIX,
            getattr(getattr(queryset, "model", None), "__name__", None),
            action,
            constraint_key,
            len(constraints),
        )
        return filtered_queryset

    def _signed_members_payload(self):
        return {
            "timestamp": self.timestamp,
            "capabilities": self.thaw_json(self.capabilities),
            "params": dict(self.params),
            "context": dict(self.context),
        }

    def verify(self, max_age_seconds=300):
        if not AC_PUBLIC_KEY_PATH:
            return False, "EXTERNAL_ACCESS_CONTROL_PUBLIC_KEY_PATH is not configured"

        if not self.signed_hash:
            return False, "No signature to verify"

        try:
            public_key = load_public_key(AC_PUBLIC_KEY_PATH)
        except OSError as exc:
            return False, f"Unable to load public key: {exc}"

        signature = binascii.unhexlify(self.signed_hash)
        if self.timestamp and (timezone.now().timestamp() - self.timestamp) > max_age_seconds:
            return False, "Signature expired"

        data_to_sign = self._signed_members_payload()
        json_text = json.dumps(
            data_to_sign,
            separators=(",", ":"),
            ensure_ascii=False,
            sort_keys=True,
        )
        json_text = (
            json_text
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )

        try:
            public_key.verify(
                signature,
                json_text.encode("utf-8"),
                ec.ECDSA(hashes.SHA3_256()),
            )
            return True, ""
        except InvalidSignature:
            logger.warning("%s AccessHandle.verify invalid signature", AC_LOG_PREFIX)
            return False, "Invalid signature"
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("%s AccessHandle.verify error=%s", AC_LOG_PREFIX, exc)
            return False, f"Signature verification error: {exc}"

    def request(self, request, **resource_ids):
        self.reset_for_new_request()
        request_uri = request.get_full_path().rstrip("/")
        payload = {
            "requesting_user": getattr(request.user, "id", None),
            "authenticated": "true" if getattr(request.user, "is_authenticated", False) else "false",
            "course": resource_ids.get("course_id"),
            "request_method": request.method,
            "request_uri": request_uri,
        }
        payload.update({
            key: value
            for key, value in resource_ids.items()
            if value is not None and key not in payload
        })
        logger.info("%s AccessHandle.request payload=%s", AC_LOG_PREFIX, payload)

        try:
            response = requests.get(AC_URL, params=payload, timeout=AC_REQUEST_TIMEOUT)
            response.raise_for_status()
            response_data = response.json()
            self.validate_server_response(response_data)
            logger.info(
                "%s AccessHandle.request received status=%s capability_keys=%s",
                AC_LOG_PREFIX,
                response.status_code,
                sorted(response_data.get("capabilities", {}).keys()),
            )
        except requests.exceptions.ConnectTimeout:
            logger.warning("%s AccessHandle.request connect timeout url=%s", AC_LOG_PREFIX, AC_URL)
            return 504, f"Connect timeout while calling AC server: {AC_URL}"
        except requests.exceptions.ReadTimeout:
            logger.warning("%s AccessHandle.request read timeout url=%s", AC_LOG_PREFIX, AC_URL)
            return 504, f"Read timeout while waiting for AC server: {AC_URL}"
        except requests.exceptions.HTTPError as exc:
            logger.warning("%s AccessHandle.request http error=%s", AC_LOG_PREFIX, exc)
            return 502, f"AC server returned error: {exc} ({exc.response.status_code})"
        except requests.exceptions.RequestException as exc:
            logger.exception("%s AccessHandle.request request exception=%s", AC_LOG_PREFIX, exc)
            return 500, f"Generic requests exception: {exc}"
        except ValueError as exc:
            logger.warning("%s AccessHandle.request invalid response error=%s", AC_LOG_PREFIX, exc)
            return 502, f"Invalid access-control response: {exc}"

        self.store_server_response(
            capabilities=response_data["capabilities"],
            params=response_data.get("params", {}),
            context=response_data.get("context", {}),
            warnings=response_data.get("warnings", []),
            errors=response_data.get("errors", []),
            signed_hash=response_data.get("signed_hash", ""),
            timestamp=response_data.get("timestamp", ""),
        )
        return response.status_code, None


@lru_cache(maxsize=1)
def load_public_key(public_key_path):
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


class ExternalAccessControlMiddleware(MiddlewareMixin):
    """Calls the external access-control service for selected LMS API routes."""

    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )

    def process_request(self, request):
        if not USE_EXTERNAL_ACCESS_CONTROL:
            return None
        logger.info("%s middleware.process_request path=%s", AC_LOG_PREFIX, getattr(request, "path", ""))
        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not USE_EXTERNAL_ACCESS_CONTROL:
            return None
        logger.info(
            "%s middleware.process_view path=%s url_name=%s",
            AC_LOG_PREFIX,
            getattr(request, "path", ""),
            getattr(getattr(request, "resolver_match", None), "url_name", None),
        )

        if not hasattr(request, "session"):
            raise ImproperlyConfigured(
                "Session middleware must run before ExternalAccessControlMiddleware."
            )

        request.user = self.resolve_authenticated_user(request)
        resource_ids = self.get_resource_ids_from_request(request)
        if not resource_ids:
            logger.info("%s middleware.process_view skipped no resource ids", AC_LOG_PREFIX)
            return None

        logger.info(
            "%s middleware.process_view resolved_user id=%s authenticated=%s resource_ids=%s",
            AC_LOG_PREFIX,
            getattr(request.user, "id", None),
            getattr(request.user, "is_authenticated", False),
            resource_ids,
        )
        access_handle = AccessHandle.current()
        status_code, error_msg = access_handle.request(request, **resource_ids)

        if status_code != 200:
            logger.warning(
                "%s middleware.process_view access request failed status=%s error=%s",
                AC_LOG_PREFIX,
                status_code,
                error_msg,
            )
            return JsonResponse(
                {"message": "External access-control error", "error": error_msg},
                status=status_code,
            )

        is_verified, verify_error = access_handle.verify()
        if not is_verified:
            logger.warning(
                "%s middleware.process_view verification failed error=%s",
                AC_LOG_PREFIX,
                verify_error,
            )
            return JsonResponse(
                {"message": "External access-control verification failed", "error": verify_error},
                status=403,
            )

        request.access_handle = access_handle
        logger.info(
            "%s middleware.process_view handle set decisions=%s",
            AC_LOG_PREFIX,
            access_handle.capability_decisions(),
        )
        return None

    # def should_defer_decision_enforcement(self, request):
    #     """Allow team membership requests to preserve legacy response semantics downstream."""
    #     return request.method == "POST" and request.path == "/api/team/v0/team_membership"

    def process_response(self, request, response):
        access_handle = AccessHandle.get_current()
        if access_handle is None:
            return response

        try:
            capability_decisions = access_handle.capability_decisions()
            demo_context = self.demo_context(request)
            response["X-IMPACD-Enforced"] = "true"
            response["X-IMPACD-Legacy-Access-Bypassed"] = "true" if demo_context["legacy_access_checks_bypassed"] else "false"
            if hasattr(response, "data") and isinstance(response.data, Mapping):
                response.data[AC_CAPABILITIES_RESPONSE_KEY] = capability_decisions
                response.data["impacd_demo"] = demo_context
                if hasattr(response, "_is_rendered") and response._is_rendered:
                    response.content = response.rendered_content
                logger.info(
                    "%s middleware.process_response injected %s into DRF response rendered=%s",
                    AC_LOG_PREFIX,
                    AC_CAPABILITIES_RESPONSE_KEY,
                    getattr(response, "_is_rendered", None),
                )
                return response
            if isinstance(response, HttpResponse) and response.headers.get("Content-Type", "").startswith("application/json"):
                try:
                    response_dict = json.loads(response.content.decode("utf-8"))
                except json.JSONDecodeError:
                    return response
                if isinstance(response_dict, Mapping):
                    response_dict[AC_CAPABILITIES_RESPONSE_KEY] = capability_decisions
                    response_dict["impacd_demo"] = demo_context
                    logger.info(
                        "%s middleware.process_response injected %s into JSON response",
                        AC_LOG_PREFIX,
                        AC_CAPABILITIES_RESPONSE_KEY,
                    )
                    return JsonResponse(response_dict, status=response.status_code, safe=False)
            return response
        finally:
            AccessHandle.clear()

    def process_exception(self, request, exception):
        access_handle = AccessHandle.get_current()
        if access_handle is None:
            return None

        try:
            if isinstance(exception, PolicyDecisionDenied):
                response = self.policy_denial_response(request, access_handle, exception)
                if response is not None:
                    return response

            if not isinstance(exception, DjangoPermissionDenied):
                return None

            response = JsonResponse(
                {
                    "message": str(exception),
                    AC_CAPABILITIES_RESPONSE_KEY: access_handle.capability_decisions(),
                    "impacd_demo": self.demo_context(request, denied_at="patched_model_save"),
                },
                status=403,
            )
            response["X-IMPACD-Enforced"] = "true"
            response["X-IMPACD-Legacy-Access-Bypassed"] = (
                "true" if self.demo_context(request)["legacy_access_checks_bypassed"] else "false"
            )
            response["X-IMPACD-Denied-At"] = "patched_model_save"
            return response
        finally:
            AccessHandle.clear()

    def policy_denial_response(self, request, access_handle, exception):
        """Build a legacy-compatible response for a status-aware policy denial."""
        username = ""
        if hasattr(request, "data") and isinstance(request.data, Mapping):
            username = request.data.get("username", "")

        if exception.reason_code in {"hidden-team-api-access", "hidden-specific-team-access"}:
            response = JsonResponse(
                {
                    "reason_code": exception.reason_code,
                    "status_code": exception.status_code,
                    AC_CAPABILITIES_RESPONSE_KEY: access_handle.capability_decisions(),
                    "impacd_demo": self.demo_context(request, denied_at="patched_model_save"),
                },
                status=exception.status_code,
            )
        elif exception.reason_code == "instructor-managed-team":
            payload = build_api_error(gettext_noop("You can't join an instructor managed team."))
            payload["reason_code"] = exception.reason_code
            payload["status_code"] = exception.status_code
            payload[AC_CAPABILITIES_RESPONSE_KEY] = access_handle.capability_decisions()
            payload["impacd_demo"] = self.demo_context(request, denied_at="patched_model_save")
            response = JsonResponse(payload, status=exception.status_code)
        elif exception.reason_code == "not-enrolled-in-course":
            payload = build_api_error(
                gettext_noop("The user {username} is not enrolled in the course associated with this team."),
                username=username,
            )
            payload["reason_code"] = exception.reason_code
            payload["status_code"] = exception.status_code
            payload[AC_CAPABILITIES_RESPONSE_KEY] = access_handle.capability_decisions()
            payload["impacd_demo"] = self.demo_context(request, denied_at="patched_model_save")
            response = JsonResponse(payload, status=exception.status_code)
        elif exception.reason_code == "incompatible-team-protection":
            payload = build_api_error(
                gettext_noop(
                    "The user {username} cannot join this team because their enrollment is incompatible with the team's access requirements."
                ),
                username=username,
            )
            payload["reason_code"] = exception.reason_code
            payload["status_code"] = exception.status_code
            payload[AC_CAPABILITIES_RESPONSE_KEY] = access_handle.capability_decisions()
            payload["impacd_demo"] = self.demo_context(request, denied_at="patched_model_save")
            response = JsonResponse(payload, status=exception.status_code)
        else:
            payload = {
                "message": str(exception),
                "reason_code": exception.reason_code,
                "status_code": exception.status_code,
                AC_CAPABILITIES_RESPONSE_KEY: access_handle.capability_decisions(),
                "impacd_demo": self.demo_context(request, denied_at="patched_model_save"),
            }
            response = JsonResponse(payload, status=exception.status_code)

        response["X-IMPACD-Enforced"] = "true"
        response["X-IMPACD-Legacy-Access-Bypassed"] = (
            "true" if self.demo_context(request)["legacy_access_checks_bypassed"] else "false"
        )
        response["X-IMPACD-Denied-At"] = "patched_model_save"
        return response

    def demo_context(self, request, denied_at=None):
        legacy_bypassed = request.GET.get("impacd_skip_legacy_access") == "1"
        context = {
            "external_access_control": "enforced",
            "legacy_access_checks_bypassed": legacy_bypassed,
            "legacy_access_bypass_flag": "impacd_skip_legacy_access=1",
            "legacy_load_block_permission_bypassed": legacy_bypassed,
            "legacy_permission_classes_bypassed": legacy_bypassed,
            "legacy_team_access_checks_bypassed": legacy_bypassed,
            "write_enforcement": "patched_model_save",
        }
        if denied_at:
            context["denied_at"] = denied_at
        return context

    def resolve_authenticated_user(self, request):
        if getattr(request.user, "is_authenticated", False):
            return request.user

        for authenticator_cls in self.authentication_classes:
            authenticator = authenticator_cls()
            try:
                authentication = authenticator.authenticate(request)
            except Exception:
                continue
            if authentication:
                user, _auth = authentication
                return user
        jwt_cookie_user = self.resolve_user_from_jwt_cookie(request)
        if jwt_cookie_user is not None:
            return jwt_cookie_user
        return request.user

    def resolve_user_from_jwt_cookie(self, request):
        header_payload = request.COOKIES.get("edx-jwt-cookie-header-payload")
        signature = request.COOKIES.get("edx-jwt-cookie-signature")
        if not header_payload or not signature:
            return None

        try:
            import base64

            from django.contrib.auth import get_user_model

            _header, payload = header_payload.split(".", 1)
            padding = "=" * (-len(payload) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(f"{payload}{padding}").decode("utf-8"))
            user_id = payload_data.get("user_id")
            if not user_id:
                return None
            return get_user_model().objects.get(id=user_id)
        except Exception:
            logger.exception("%s middleware.resolve_user_from_jwt_cookie failed", AC_LOG_PREFIX)
            return None

    def get_resource_ids_from_request(self, request):
        resolver_match = getattr(request, "resolver_match", None)
        if resolver_match and resolver_match.url_name == "dates-tab":
            resource_ids = {"course_id": resolver_match.kwargs.get("course_key_string")}
            logger.info("%s middleware.get_resource_ids_from_request resource_ids=%s", AC_LOG_PREFIX, resource_ids)
            return resource_ids
        if resolver_match and resolver_match.url_name == "course_gradebook":
            resource_ids = {"course_id": resolver_match.kwargs.get("course_id")}
            logger.info("%s middleware.get_resource_ids_from_request resource_ids=%s", AC_LOG_PREFIX, resource_ids)
            return resource_ids
        if resolver_match and resolver_match.url_name == "course_gradebook_grading_info":
            resource_ids = {"course_id": resolver_match.kwargs.get("course_id")}
            logger.info("%s middleware.get_resource_ids_from_request resource_ids=%s", AC_LOG_PREFIX, resource_ids)
            return resource_ids
        if resolver_match and resolver_match.url_name == "xblock_handler":
            kwargs = resolver_match.kwargs
            if "usage_key" in kwargs and "handler_name" in kwargs:
                usage_key = kwargs.get("usage_key")
                user_id = kwargs.get("user_id")
                secure_token = kwargs.get("secure_token")
                resource_ids = {
                    "course_id": str(getattr(usage_key, "course_key", "") or ""),
                    "usage_key": str(usage_key),
                    "xblock_user_id": str(user_id) if user_id is not None else None,
                    "user_token": f"{user_id}-{secure_token}" if user_id and secure_token else None,
                    "handler_name": kwargs.get("handler_name"),
                    "suffix": kwargs.get("suffix"),
                }
                logger.info("%s middleware.get_resource_ids_from_request resource_ids=%s", AC_LOG_PREFIX, resource_ids)
                return resource_ids
        if resolver_match and resolver_match.url_name == "team_membership_list" and request.method == "POST":
            request_data = {}
            if request.POST:
                request_data = request.POST
            else:
                try:
                    request_data = json.loads((request.body or b"{}").decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    request_data = {}
            team_id = request_data.get("team_id")
            username = request_data.get("username")
            resource_ids = {"team_id": team_id, "username": username}
            team = None
            access_subject = None
            if team_id:
                try:
                    from lms.djangoapps.teams.models import CourseTeam

                    team = CourseTeam.objects.get(team_id=team_id)
                    resource_ids["course_id"] = str(team.course_id)
                except CourseTeam.DoesNotExist:
                    pass
            if username:
                try:
                    from django.contrib.auth import get_user_model

                    UserModel = get_user_model()
                    access_subject = UserModel.objects.get(username=username)
                    resource_ids["access_subject"] = access_subject.id
                    resource_ids["access_subject_username"] = access_subject.username
                except UserModel.DoesNotExist:
                    pass
            if "access_subject" not in resource_ids and getattr(request.user, "is_authenticated", False):
                resource_ids["access_subject"] = request.user.id
                resource_ids["access_subject_username"] = request.user.username

            if team is not None:
                from lms.djangoapps.teams.api import can_user_modify_team, has_specific_team_access, has_team_api_access

                resource_ids["team_api_access_granted"] = str(
                    has_team_api_access(request.user, team.course_id, access_username=username)
                ).lower()
                resource_ids["specific_team_access_granted"] = str(
                    has_specific_team_access(request.user, team)
                ).lower()
                resource_ids["team_modification_allowed"] = str(
                    can_user_modify_team(request.user, team)
                ).lower()

            logger.info("%s middleware.get_resource_ids_from_request resource_ids=%s", AC_LOG_PREFIX, resource_ids)
            return resource_ids
        return {}
