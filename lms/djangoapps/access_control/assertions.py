from datetime import date, datetime
from collections.abc import Mapping

from django.db.models import Q
from django.utils.dateparse import parse_datetime

from lms.djangoapps.access_control.errors import AssertionValidationError, UnsupportedAssertionError


LOOKUP_MAP = {
    "eq": "exact",
    "neq": "exact",
    "gt": "gt",
    "gte": "gte",
    "lt": "lt",
    "lte": "lte",
}


def constraints_to_assertions(constraints, constraint_key, context=None):
    assertions = {}
    for index, constraint in enumerate(constraints or []):
        constraint_values = constraint.get(constraint_key) if isinstance(constraint, Mapping) else None
        if not constraint_values:
            continue
        assertion_name = unique_assertion_name(
            assertions,
            constraint_display_name(constraint, constraint_values, index),
        )
        assertions[assertion_name] = constraint_expression_tree(
            constraint_values,
            context=context,
        )
    return assertions


def constraint_display_name(constraint, constraint_values, index):
    explicit_name = None
    if isinstance(constraint, Mapping):
        explicit_name = constraint.get("name") or constraint.get("assertion_name")
    if isinstance(explicit_name, str) and explicit_name.strip():
        return explicit_name.strip()

    resource_action_name = derive_resource_action_name(constraint)
    if resource_action_name:
        return resource_action_name

    derived_name = derive_assertion_name(constraint_values)
    if derived_name:
        return derived_name
    return f"assertion_{index}"


def derive_resource_action_name(constraint):
    if not isinstance(constraint, Mapping):
        return None

    resource = normalize_assertion_label(constraint.get("resource"))
    action = normalize_assertion_label(constraint.get("action"))
    if resource and action:
        return f"{resource}__{action}"
    return resource or action


def derive_assertion_name(values):
    if is_group_node(values, "and"):
        return combine_assertion_names("and", values["and"])
    if is_group_node(values, "or"):
        return combine_assertion_names("or", values["or"])
    if is_leaf_node(values):
        return normalize_assertion_label(values.get("field"))
    if isinstance(values, Mapping):
        names = [normalize_assertion_label(field_name) for field_name in values.keys()]
        return "__and__".join(name for name in names if name)
    return None


def combine_assertion_names(operator, children):
    names = []
    for child in children or []:
        name = derive_assertion_name(child)
        if name:
            names.append(name)
    if not names:
        return None
    if len(names) == 1:
        return names[0]
    joiner = f"__{operator}__"
    return joiner.join(names)


def normalize_assertion_label(value):
    if not isinstance(value, str):
        return None
    label = value.strip().replace('.', '__')
    return label or None


def unique_assertion_name(assertions, base_name):
    if base_name not in assertions:
        return base_name

    suffix = 2
    while f"{base_name}_{suffix}" in assertions:
        suffix += 1
    return f"{base_name}_{suffix}"


def constraint_expression_tree(values, context=None):
    if is_group_node(values, "and"):
        return {
            "and": [
                constraint_expression_tree(child, context=context)
                for child in values["and"]
            ]
        }
    if is_group_node(values, "or"):
        return {
            "or": [
                constraint_expression_tree(child, context=context)
                for child in values["or"]
            ]
        }
    if is_leaf_node(values):
        return normalize_constraint_leaf(values, context=context)
    if not isinstance(values, Mapping):
        raise UnsupportedAssertionError(f"Unsupported constraint expression: {values}")

    leaves = [
        field_constraint_leaf(field_name, value, context=context)
        for field_name, value in (values or {}).items()
    ]
    if not leaves:
        return {}
    if len(leaves) == 1:
        return leaves[0]
    return {"and": leaves}


def field_constraint_leaf(field_name, value, context=None):
    if isinstance(value, Mapping) and "op" in value:
        leaf = {
            "field": field_name,
            "op": value["op"],
        }
        if "value" in value:
            leaf["value"] = value["value"]
        if "other_field" in value:
            leaf["other_field"] = value["other_field"]
        if "value_from" in value:
            leaf["value"] = resolve_context_value(context, value["value_from"])
        return normalize_constraint_leaf(leaf, context=context)
    return {"field": field_name, "op": "eq", "value": value}


def normalize_constraint_leaf(node, context=None):
    leaf = dict(node)
    if "value_from" in leaf:
        if "value" in leaf or "other_field" in leaf:
            raise UnsupportedAssertionError(
                f"Constraint leaf cannot mix value_from with value or other_field: {node}"
            )
        leaf["value"] = resolve_context_value(context, leaf.pop("value_from"))
    parse_leaf(leaf)
    return leaf


def is_leaf_node(node):
    return isinstance(node, Mapping) and "field" in node and "op" in node

# Creating Queryset predicates from constraint expressions

def apply_assertions_to_queryset(queryset, assertions, policy_name=None, strict=True):
    predicate = None
    for node in iter_selected_assertions(assertions, policy_name):
        node_predicate = build_queryset_predicate(node, strict=strict)
        if node_predicate is None:
            continue
        predicate = node_predicate if predicate is None else predicate & node_predicate

    if predicate is None:
        return queryset
    return queryset.filter(predicate)


def build_queryset_predicate(node, strict=True):
    if not node:
        return None

    if is_group_node(node, "and"):
        predicate = None
        for child in node["and"]:
            child_predicate = build_queryset_predicate(child, strict=strict)
            if child_predicate is None:
                continue
            predicate = child_predicate if predicate is None else predicate & child_predicate
        return predicate

    if is_group_node(node, "or"):
        predicate = None
        for child in node["or"]:
            child_predicate = build_queryset_predicate(child, strict=strict)
            if child_predicate is None:
                continue
            predicate = child_predicate if predicate is None else predicate | child_predicate
        return predicate

    try:
        return build_leaf_predicate(node)
    except UnsupportedAssertionError:
        if strict:
            raise
        return None


def build_leaf_predicate(node):
    field_name, operator, value, other_field = parse_leaf(node)
    if other_field is not None:
        raise UnsupportedAssertionError("Cross-field queryset constraints are not supported")

    lookup = LOOKUP_MAP[operator]
    predicate = Q(**{f"{field_name}__{lookup}": value})
    if operator == "neq":
        return ~predicate
    return predicate

# Applying checks on payload

def validate_payload_against_assertions(payload, assertions, policy_name=None, strict=True):
    failed_policies = []
    selected_assertions = select_assertions(assertions, policy_name)
    for selected_policy_name, node in selected_assertions.items():
        if not evaluate_assertion_node(node, payload, strict=strict):
            failed_policies.append(selected_policy_name)

    if failed_policies:
        raise AssertionValidationError(
            {
                "error_msg": "Payload violates access-control constraints",
                "policies": failed_policies,
            }
        )
    return True


def evaluate_assertion_node(node, payload, strict=True):
    if not node:
        return True

    if is_group_node(node, "and"):
        return all(evaluate_assertion_node(child, payload, strict=strict) for child in node["and"])

    if is_group_node(node, "or"):
        return any(evaluate_assertion_node(child, payload, strict=strict) for child in node["or"])

    try:
        return evaluate_leaf(node, payload)
    except UnsupportedAssertionError:
        if strict:
            raise
        return True


def evaluate_leaf(node, payload):
    field_name, operator, value, other_field = parse_leaf(node)
    left_value = resolve_payload_value(payload, field_name)
    right_value = value if other_field is None else resolve_payload_value(payload, other_field)
    left_value, right_value = coerce_comparable_values(left_value, right_value)

    if operator == "eq":
        return left_value == right_value
    if operator == "neq":
        return left_value != right_value
    if left_value is None or right_value is None:
        return False
    if operator == "gt":
        return left_value > right_value
    if operator == "gte":
        return left_value >= right_value
    if operator == "lt":
        return left_value < right_value
    if operator == "lte":
        return left_value <= right_value
    raise UnsupportedAssertionError(f"Unsupported operator: {operator}")


def coerce_comparable_values(left_value, right_value):
    left_datetime = coerce_datetime(left_value)
    right_datetime = coerce_datetime(right_value)
    if left_datetime is not None and right_datetime is not None:
        return left_datetime, right_datetime
    return left_value, right_value


def coerce_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        return parse_datetime(normalized)
    return None


def parse_leaf(node):
    if not isinstance(node, Mapping):
        raise UnsupportedAssertionError(f"Unsupported assertion node: {node}")
    if "field" not in node or "op" not in node:
        raise UnsupportedAssertionError(f"Assertion leaf must contain field and op: {node}")
    if "and" in node or "or" in node:
        raise UnsupportedAssertionError(f"Invalid assertion leaf: {node}")

    has_value = "value" in node
    has_other_field = "other_field" in node
    if has_value == has_other_field:
        raise UnsupportedAssertionError(
            f"Assertion leaf must contain exactly one of value or other_field: {node}"
        )

    field_name = normalize_field_name(node["field"])
    operator = normalize_operator(node["op"])
    value = node.get("value")
    other_field = normalize_field_name(node["other_field"]) if has_other_field else None
    return field_name, operator, value, other_field


def is_group_node(node, key):
    return isinstance(node, Mapping) and key in node


def normalize_operator(operator):
    normalized = str(operator).strip().lower()
    if normalized not in LOOKUP_MAP:
        raise UnsupportedAssertionError(f"Unsupported operator: {operator}")
    return normalized


def normalize_field_name(field_name):
    if not isinstance(field_name, str) or not field_name.strip():
        raise UnsupportedAssertionError(f"Unsupported field path: {field_name}")
    return field_name.strip().replace(".", "__")


def select_assertions(assertions, policy_name=None):
    assertions = assertions or {}
    if policy_name is None:
        return assertions
    node = assertions.get(policy_name)
    if node is None:
        return {}
    return {policy_name: node}


def iter_selected_assertions(assertions, policy_name=None):
    return select_assertions(assertions, policy_name).values()


def resolve_context_value(context, value_path):
    if not value_path:
        raise UnsupportedAssertionError(f"Unsupported context value path: {value_path}")
    value = resolve_payload_value(context or {}, normalize_field_name(str(value_path)))
    if value is None:
        raise UnsupportedAssertionError(f"Context value not found: {value_path}")
    return value


def resolve_payload_value(payload, field_name):
    current = payload
    parts = field_name.split("__")
    for part in parts:
        current = resolve_field_part(current, part)
    if current is not None:
        return current
    return resolve_equivalent_id_path(payload, parts)


def resolve_equivalent_id_path(payload, parts):
    if len(parts) < 2 or parts[-1] != "id":
        return None
    canonical_field_name = "__".join(parts[:-1]) + "_id"
    return resolve_direct_value(payload, canonical_field_name)


def resolve_direct_value(payload, field_name):
    current = payload
    for part in field_name.split("__"):
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
            if callable(current):
                current = current()
    return current


def resolve_field_part(current, part):
    if isinstance(current, Mapping):
        if part in current:
            return current.get(part)
        return resolve_related_object_id(current.get(related_object_name(part)), part)

    value = getattr(current, part, None)
    if callable(value):
        value = value()
    if value is not None:
        return value

    return resolve_related_object_id(getattr(current, related_object_name(part), None), part)


def related_object_name(field_name):
    if field_name.endswith("_id"):
        return field_name[:-3]
    return field_name


def resolve_related_object_id(value, field_name):
    if value is None or not field_name.endswith("_id"):
        return None
    if isinstance(value, (str, int)):
        return value

    related_id = getattr(value, "id", None)
    if callable(related_id):
        related_id = related_id()
    return related_id
