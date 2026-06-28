"""App config for LMS external access control."""

import logging

from cryptography.hazmat.primitives import serialization
from django.apps import AppConfig
from django.core.exceptions import PermissionDenied

from lms.djangoapps.access_control.assertions import constraints_to_assertions, validate_payload_against_assertions
from lms.djangoapps.access_control.errors import AssertionValidationError, build_policy_decision_denied
from lms.djangoapps.access_control.settings import AC_LOG_PREFIX, AC_PUBLIC_KEY_PATH, USE_EXTERNAL_ACCESS_CONTROL

logger = logging.getLogger(__name__)


class AccessControlConfig(AppConfig):
    name = "lms.djangoapps.access_control"
    label = "lms_access_control"
    verbose_name = "LMS External Access Control"

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self.public_key = None

    def load_public_key(self, public_key_path):
        with open(public_key_path, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(key_file.read())
        logger.info("%s apps.load_public_key path=%s", AC_LOG_PREFIX, public_key_path)

    def ready(self):
        if not USE_EXTERNAL_ACCESS_CONTROL:
            logger.info("%s apps.ready skipped external access control disabled", AC_LOG_PREFIX)
            return

        self.load_public_key(AC_PUBLIC_KEY_PATH)

        import django.db.models as models

        from lms.djangoapps.access_control import middleware as ac_m

        if getattr(models.Manager, "_access_control_patched", False):
            logger.info("%s apps.ready skipped manager already patched", AC_LOG_PREFIX)
            return

        models.Manager._access_control_original_get_queryset = models.Manager.get_queryset
        _original_get_queryset = models.Manager._access_control_original_get_queryset
        models.Model._access_control_original_save = models.Model.save
        _original_save = models.Model._access_control_original_save

        access_controlled_model_names = {
            "BlockCompletion",
            "CourseAccessRole",
            "CourseEnrollment",
            "CourseMode",
            "CourseTeamMembership",
            "CourseOverview",
            "PersistentCourseGrade",
            "PersistentSubsectionGrade",
            "VerificationDeadline",
            "ContentTypeGatingConfig",
        }

        def model_name_for_orm_object(obj):
            if isinstance(obj, models.Model):
                return obj.__class__.__name__
            model = getattr(obj, "model", None)
            if isinstance(model, type) and issubclass(model, models.Model):
                return model.__name__
            return None

        def is_access_controlled_model(obj):
            return model_name_for_orm_object(obj) in access_controlled_model_names

        def normalize_payload_value(value):
            if value is None or isinstance(value, (bool, int, float, str)):
                return value
            return str(value)

        def model_payload(instance):
            payload = {
                "model": instance.__class__.__name__,
                "pk": normalize_payload_value(instance.pk),
            }
            for field in instance._meta.concrete_fields:
                value = normalize_payload_value(getattr(instance, field.attname, None))
                payload[field.attname] = value
                if field.name != field.attname:
                    payload[field.name] = value
            return payload

        def get_verified_access_handle(context_level):
            access_handle = ac_m.AccessHandle.get_current()
            if access_handle is None:
                return None
            if not access_handle.has_server_response():
                raise PermissionDenied(f"[{context_level}] Access handle has no server response")

            is_verified, error = access_handle.verify()
            if not is_verified:
                raise PermissionDenied(f"[{context_level}] Invalid access handle: {error}")
            return access_handle

        def mapped_policy_denial(capabilities):
            for capability_name, capability in capabilities.items():
                if not capability or capability.get("decision", False):
                    continue
                exception = build_policy_decision_denied(capability_name, capability)
                if exception is not None:
                    return exception
            return None

        # def patched_get_queryset(self):
        #     queryset = _original_get_queryset(self)
        #     if not is_access_controlled_model(self):
        #         return queryset
        #     logger.info(
        #         "%s patched_get_queryset model=%s",
        #         AC_LOG_PREFIX,
        #         getattr(getattr(queryset, "model", None), "__name__", None),
        #     )

        #     access_handle = get_verified_access_handle("Manager.get_queryset")
        #     if access_handle is None:
        #         logger.info("%s patched_get_queryset no access handle present", AC_LOG_PREFIX)
        #         return queryset

        #     capabilities = access_handle.capabilities_for_request()
        #     if not capabilities:
        #         logger.warning("%s Manager.get_queryset no capabilities resolved for request", AC_LOG_PREFIX)
        #         raise PermissionDenied("[Manager.get_queryset] No access-control capabilities found for request route")
        #     if len(capabilities) != 1:
        #         logger.warning(
        #             "%s Manager.get_queryset expected single capability for route but found=%s",
        #             AC_LOG_PREFIX,
        #             sorted(capabilities.keys()),
        #         )
        #         raise PermissionDenied(
        #             "[Manager.get_queryset] Expected exactly one access-control capability for request route"
        #         )

        #     capability_name = next(iter(capabilities))
        #     selected_capabilities = {capability_name: capabilities[capability_name]}

        #     try:
        #         access_handle.assert_capability_decisions(selected_capabilities)
        #     except (AssertionValidationError, PermissionError) as error:
        #         detail = getattr(error, "detail", str(error))
        #         logger.warning("%s patched_get_queryset denied detail=%s", AC_LOG_PREFIX, detail)
        #         raise PermissionDenied(detail) from error

        #     filtered_queryset = access_handle.filter_queryset(
        #         queryset,
        #         capability_names=(capability_name,),
        #         action="read",
        #         constraint_key="query_constraints",
        #     )
        #     logger.info(
        #         "%s patched_get_queryset allowed model=%s capability=%s",
        #         AC_LOG_PREFIX,
        #         getattr(getattr(queryset, "model", None), "__name__", None),
        #         capability_name,
        #     )
        #     return filtered_queryset

        def patched_save(self, *args, **kwargs):
            if not is_access_controlled_model(self):
                return _original_save(self, *args, **kwargs)

            logger.info("%s patched_save model=%s", AC_LOG_PREFIX, self.__class__.__name__)
            access_handle = get_verified_access_handle("Model.save")
            if access_handle is None:
                logger.info("%s patched_save no access handle present", AC_LOG_PREFIX)
                return _original_save(self, *args, **kwargs)

            capabilities = access_handle.capabilities_for_request()
            if not capabilities:
                logger.warning("%s Model.save no capabilities resolved for request", AC_LOG_PREFIX)
                raise PermissionDenied("[Model.save] No access-control capabilities found for request route")
            if len(capabilities) != 1:
                logger.warning(
                    "%s Model.save expected single capability for route but found=%s",
                    AC_LOG_PREFIX,
                    sorted(capabilities.keys()),
                )
                raise PermissionDenied(
                    "[Model.save] Expected exactly one access-control capability for request route"
                )

            capability_name = next(iter(capabilities))
            selected_capabilities = {capability_name: capabilities[capability_name]}

            mapped_exception = mapped_policy_denial(selected_capabilities)
            if mapped_exception is not None:
                translated_exception = getattr(mapped_exception, "mapped_error", None) or mapped_exception
                logger.warning(
                    "%s patched_save translated policy denial to exception=%s capability=%s",
                    AC_LOG_PREFIX,
                    translated_exception.__class__.__name__,
                    capability_name,
                )
                raise translated_exception

            try:
                access_handle.assert_capability_decisions(selected_capabilities)
                constraints = access_handle.matching_constraints(
                    capability_names=(capability_name,),
                    resource=self.__class__.__name__,
                    action="write",
                )
                validate_payload_against_assertions(
                    model_payload(self),
                    constraints_to_assertions(
                        constraints,
                        "mutation_constraints",
                        context=access_handle.context,
                    ),
                    strict=True,
                )
            except PermissionError as error:
                detail = getattr(error, "detail", str(error))
                logger.warning("%s patched_save denied detail=%s", AC_LOG_PREFIX, detail)
                raise PermissionDenied(detail) from error
            except AssertionValidationError as error:
                detail = getattr(error, "detail", str(error))
                logger.warning("%s patched_save denied detail=%s", AC_LOG_PREFIX, detail)
                raise PermissionDenied(detail) from error

            logger.info(
                "%s patched_save allowed model=%s capability=%s",
                AC_LOG_PREFIX,
                self.__class__.__name__,
                capability_name,
            )
            return _original_save(self, *args, **kwargs)

        # models.Manager.get_queryset = patched_get_queryset
        models.Model.save = patched_save
        models.Manager._access_control_patched = True
        logger.info("%s apps.ready patched Manager.get_queryset and Model.save", AC_LOG_PREFIX)
