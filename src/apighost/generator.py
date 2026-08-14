"""
APIGhost Data Generator — Three-Tier Value Resolution Engine

The hardest problem in automated API testing: generating payloads that
pass real-world input validation. Most tools send {"username": "string"}
and get 400 Bad Request. This module solves that with a three-tier
value resolution engine that produces valid, contextually aware payloads.

Architecture:
    Tier 1 (Spec Examples):
        Extract `example`, `examples`, and `default` values directly from
        the OpenAPI schema. These are the most reliable values since the
        API author explicitly provided them.

    Tier 2 (Format Heuristics):
        When no examples exist, use a comprehensive mapping system based
        on `format` hints, property names, and type constraints to generate
        realistic values. Handles emails, UUIDs, dates, phone numbers,
        prices, and dozens of other field types.

    Tier 3 (Dependency Prefetch):
        The critical differentiator. Scans request body schemas for foreign
        key fields (e.g., `product_id`), finds the corresponding GET
        endpoint in the spec, calls it with User A's auth token, and
        harvests a real, valid ID. This is what prevents the "Validation
        Wall" — where a POST fails because department_id=0 doesn't exist.

Output:
    A dict with keys: path_params, query_params, headers, body.
"""

from __future__ import annotations

import logging
import random
import re
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from apighost.models import Endpoint, HttpMethod

logger = logging.getLogger(__name__)

# Optional httpx import — module works without it installed
try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HTTPX_AVAILABLE = False

# ─────────────────────────────────────────────
# Constants & Heuristic Tables
# ─────────────────────────────────────────────

# Foreign-key pattern: field names ending in _id, _uuid, _key, _ref
FK_PATTERN = re.compile(
    r"^(.+?)(?:_id|_uuid|_key|_ref|Id|ID)$", re.IGNORECASE
)

# Realistic first / last names for payload generation
_FIRST_NAMES = [
    "Alice", "Bob", "Carol", "David", "Elena", "Frank",
    "Grace", "Hector", "Irene", "James", "Karen", "Leo",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones",
    "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
]
_CITIES = [
    "New York", "London", "Tokyo", "Berlin", "Sydney",
    "Toronto", "Paris", "Mumbai", "São Paulo", "Seoul",
]
_COUNTRIES = [
    "United States", "United Kingdom", "Japan", "Germany",
    "Australia", "Canada", "France", "India", "Brazil", "South Korea",
]
_LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
)
_STATUSES = ["active", "pending", "completed", "inactive"]
_ROLES = ["user", "admin", "moderator", "editor"]

# ─────────────────────────────────────────────
# Property name → generator mappings
# ─────────────────────────────────────────────

# Maps a regex pattern to a callable that produces a value
_NAME_HEURISTICS: list[tuple[re.Pattern, Any]] = [
    # UUID
    (re.compile(r"uuid", re.I), "uuid"),
    # Email-like
    (re.compile(r"e[\-_]?mail", re.I), "email"),
    # Password
    (re.compile(r"pass(?:word)?", re.I), "password"),
    # Phone
    (re.compile(r"phone|mobile|cell|fax", re.I), "phone"),
    # URL / Website
    (re.compile(r"url|website|homepage|link|uri", re.I), "url"),
    # Price / Money
    (re.compile(r"price|amount|cost|total|fee|salary|balance", re.I), "price"),
    # Quantity / Count
    (re.compile(r"quantity|count|qty|num|number_of", re.I), "quantity"),
    # Description / Bio / Comment
    (re.compile(r"descr|comment|bio|note|detail|body|text|message", re.I), "description"),
    # Name fields (must be after email/password)
    (re.compile(r"first[\-_]?name", re.I), "first_name"),
    (re.compile(r"last[\-_]?name|surname|family[\-_]?name", re.I), "last_name"),
    (re.compile(r"(?:user[\-_]?)?name|display[\-_]?name|full[\-_]?name", re.I), "name"),
    # Address
    (re.compile(r"address|street", re.I), "address"),
    (re.compile(r"^city$", re.I), "city"),
    (re.compile(r"^country$", re.I), "country"),
    (re.compile(r"zip|postal[\-_]?code", re.I), "zip"),
    (re.compile(r"^state$|province", re.I), "state"),
    # Title / Subject
    (re.compile(r"^title$|^subject$|headline", re.I), "title"),
    # Status / Role / Type
    (re.compile(r"^status$", re.I), "status"),
    (re.compile(r"^role$|^type$|^category$", re.I), "role"),
    # Rating
    (re.compile(r"rating|score|stars", re.I), "rating"),
    # Age
    (re.compile(r"^age$", re.I), "age"),
]


# ─────────────────────────────────────────────
# Tier 3: Dependency Prefetcher
# ─────────────────────────────────────────────


class DependencyPrefetcher:
    """
    Scans request body schemas for foreign key fields and pre-fetches
    real, valid IDs from the target API before payload generation.

    This prevents the "Validation Wall" — where a POST /orders fails
    because product_id=0 doesn't exist in the database.

    Usage:
        prefetcher = DependencyPrefetcher(spec, client, token)
        fk_values = await prefetcher.prefetch_foreign_keys(schema)
        # fk_values = {"product_id": 42, "category_id": 7}
    """

    def __init__(
        self,
        resolved_spec: dict[str, Any],
        client: Any | None = None,
        auth_token: str | None = None,
    ):
        """
        Initialize the prefetcher.

        Args:
            resolved_spec: Fully resolved OpenAPI spec dict.
            client: An httpx.AsyncClient instance for making API calls.
                    If None, prefetching is disabled (falls back to Tier 2).
            auth_token: Bearer token for User A's authenticated session.
        """
        self.spec = resolved_spec
        self.client = client
        self.auth_token = auth_token
        self._cache: dict[str, Any] = {}
        self._endpoint_map: dict[str, str] = {}
        self._build_endpoint_map()

    def _build_endpoint_map(self) -> None:
        """
        Build a mapping from resource names to their GET (list) endpoints.

        Scans the spec for GET endpoints that return lists of resources
        or individual resources, and maps the resource name to the path.

        Example:
            "product" → "/api/products"
            "category" → "/api/categories"
        """
        paths = self.spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            # Only look at GET endpoints
            get_op = methods.get("get")
            if not isinstance(get_op, dict):
                continue

            # Extract the resource name from the path
            # /api/products → "product"
            # /api/v1/categories → "category"
            segments = [
                s for s in path.split("/")
                if s and not s.startswith("{") and s not in ("api", "v1", "v2", "v3")
            ]
            if not segments:
                continue

            resource = segments[-1].rstrip("s")  # "products" → "product"
            resource_lower = resource.lower()

            # Prefer list endpoints (no path params) over detail endpoints
            has_path_params = bool(re.search(r"\{[^}]+\}", path))
            existing = self._endpoint_map.get(resource_lower)

            if existing is None or not has_path_params:
                self._endpoint_map[resource_lower] = path

        logger.debug(
            "DependencyPrefetcher endpoint map: %s", self._endpoint_map
        )

    def _find_endpoint_for_resource(self, resource_name: str) -> str | None:
        """
        Find a GET endpoint that can serve IDs for a given resource name.

        Args:
            resource_name: The singular resource name (e.g., "product").

        Returns:
            The API path string, or None if not found.
        """
        resource_lower = resource_name.lower()

        # Direct match
        if resource_lower in self._endpoint_map:
            return self._endpoint_map[resource_lower]

        # Try plural
        if resource_lower + "s" in self._endpoint_map:
            return self._endpoint_map[resource_lower + "s"]

        # Try without trailing 's'
        if resource_lower.endswith("s"):
            singular = resource_lower[:-1]
            if singular in self._endpoint_map:
                return self._endpoint_map[singular]

        # Fuzzy: substring match
        for key, path in self._endpoint_map.items():
            if resource_lower in key or key in resource_lower:
                return path

        return None

    def _extract_fk_fields(self, schema: dict[str, Any]) -> list[tuple[str, str]]:
        """
        Scan a schema and extract fields that look like foreign keys.

        Returns:
            List of (field_name, resource_name) tuples.
            e.g., [("product_id", "product"), ("category_id", "category")]
        """
        fk_fields: list[tuple[str, str]] = []
        properties = schema.get("properties", {})

        for field_name, field_schema in properties.items():
            if not isinstance(field_schema, dict):
                continue

            match = FK_PATTERN.match(field_name)
            if match:
                resource_name = match.group(1)
                fk_fields.append((field_name, resource_name))

        # Also check allOf / oneOf / anyOf
        for combiner in ("allOf", "oneOf", "anyOf"):
            sub_schemas = schema.get(combiner, [])
            if isinstance(sub_schemas, list):
                for sub in sub_schemas:
                    if isinstance(sub, dict):
                        fk_fields.extend(self._extract_fk_fields(sub))

        return fk_fields

    async def prefetch_foreign_keys(
        self, schema: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Main method: scan the schema for FK fields and fetch real IDs.

        For each foreign key field found in the schema, this method:
        1. Identifies the target resource name
        2. Finds a GET endpoint for that resource in the spec
        3. Calls the endpoint to harvest a real, valid ID
        4. Caches the result to avoid repeated API calls

        Args:
            schema: The request body schema to scan.

        Returns:
            Dict mapping field names to real values fetched from the API.
            e.g., {"product_id": 42, "category_id": 7}
        """
        if not self.client or not _HTTPX_AVAILABLE:
            logger.debug(
                "DependencyPrefetcher: No client available, skipping prefetch."
            )
            return {}

        fk_fields = self._extract_fk_fields(schema)
        if not fk_fields:
            return {}

        result: dict[str, Any] = {}

        for field_name, resource_name in fk_fields:
            # Check cache first
            if field_name in self._cache:
                result[field_name] = self._cache[field_name]
                logger.debug(
                    "Prefetch cache hit: %s = %s",
                    field_name, self._cache[field_name],
                )
                continue

            endpoint_path = self._find_endpoint_for_resource(resource_name)
            if not endpoint_path:
                logger.warning(
                    "Prefetch: No GET endpoint found for resource '%s' "
                    "(field: %s)",
                    resource_name, field_name,
                )
                continue

            # Build the request
            fetched_id = await self._fetch_id_from_endpoint(
                endpoint_path, resource_name, field_name
            )
            if fetched_id is not None:
                result[field_name] = fetched_id
                self._cache[field_name] = fetched_id

        return result

    async def _fetch_id_from_endpoint(
        self,
        endpoint_path: str,
        resource_name: str,
        field_name: str,
    ) -> Any | None:
        """
        Call a GET endpoint and extract a valid ID from the response.

        Args:
            endpoint_path: The API path to call (e.g., "/api/products").
            resource_name: The resource name for logging.
            field_name: The field name we're trying to fill.

        Returns:
            A valid ID value, or None if the fetch failed.
        """
        headers: dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            # Resolve any path params with dummy values (for list endpoints
            # this shouldn't have params, but handle gracefully)
            resolved_path = re.sub(r"\{[^}]+\}", "1", endpoint_path)

            response = await self.client.get(
                resolved_path, headers=headers, timeout=10.0
            )

            if response.status_code >= 400:
                logger.warning(
                    "Prefetch %s returned HTTP %d",
                    endpoint_path, response.status_code,
                )
                return None

            data = response.json()
            return self._extract_id_from_response(data, field_name)

        except Exception as exc:
            logger.warning(
                "Prefetch failed for %s (%s): %s",
                endpoint_path, field_name, exc,
            )
            return None

    def _extract_id_from_response(
        self, data: Any, field_name: str
    ) -> Any | None:
        """
        Extract an ID value from an API response body.

        Handles both list responses (pick first item) and single-object
        responses.

        Args:
            data: The parsed JSON response.
            field_name: The target field name (e.g., "product_id").

        Returns:
            The extracted ID, or None.
        """
        # If response is a list, take the first item
        if isinstance(data, list) and data:
            data = data[0]

        # Some APIs wrap results in a container
        if isinstance(data, dict):
            # Check for common wrapper keys
            for wrapper in ("data", "results", "items", "records"):
                wrapped = data.get(wrapper)
                if isinstance(wrapped, list) and wrapped:
                    data = wrapped[0]
                    break

        if not isinstance(data, dict):
            return None

        # Try exact field name match first
        if field_name in data:
            return data[field_name]

        # Try common ID field names
        for id_key in ("id", "Id", "ID", "_id", "uuid"):
            if id_key in data:
                return data[id_key]

        # Try any field ending in _id
        for key, value in data.items():
            if key.lower().endswith("_id") or key.lower() == "id":
                return value

        return None

    def clear_cache(self) -> None:
        """Clear the prefetch cache."""
        self._cache.clear()
        logger.debug("DependencyPrefetcher cache cleared.")


# ─────────────────────────────────────────────
# Main Generator: Three-Tier Value Resolution
# ─────────────────────────────────────────────


class DataGenerator:
    """
    Three-Tier Value Resolution Engine for generating valid HTTP payloads.

    Given an Endpoint object (with its schemas, parameters, and constraints),
    this class produces a complete request payload dict containing path_params,
    query_params, headers, and body — all with values that should pass the
    API's input validation.

    Usage:
        generator = DataGenerator(resolved_spec)
        payload = generator.generate_payload(endpoint)
        # payload = {
        #     "path_params": {"id": 42},
        #     "query_params": {},
        #     "headers": {},
        #     "body": {"product_id": 7, "quantity": 3}
        # }
    """

    def __init__(
        self,
        resolved_spec: dict[str, Any],
        prefetcher: DependencyPrefetcher | None = None,
    ):
        """
        Initialize the DataGenerator.

        Args:
            resolved_spec: The fully resolved OpenAPI spec dict.
            prefetcher: Optional DependencyPrefetcher for Tier 3 resolution.
                        If None, only Tiers 1 and 2 are used.
        """
        self.spec = resolved_spec
        self.prefetcher = prefetcher
        self._prefetched_values: dict[str, Any] = {}

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def generate_payload(self, endpoint: Endpoint) -> dict[str, Any]:
        """
        Generate a complete HTTP request payload for the given endpoint.

        Produces path parameters, query parameters, headers, and a request
        body — all with values resolved through the three-tier system.

        Args:
            endpoint: The Endpoint object to generate a payload for.

        Returns:
            Dict with keys: path_params, query_params, headers, body.
        """
        logger.info(
            "Generating payload for %s %s", endpoint.method.value, endpoint.path
        )

        # Generate parameters (path, query, header)
        path_params, query_params, headers = self._generate_parameters(endpoint)

        # Generate request body (for POST, PUT, PATCH)
        body: dict[str, Any] = {}
        if endpoint.request_body_schema:
            body = self._generate_body(endpoint.request_body_schema)

        payload = {
            "path_params": path_params,
            "query_params": query_params,
            "headers": headers,
            "body": body,
        }

        logger.debug("Generated payload: %s", payload)
        return payload

    async def generate_payload_async(self, endpoint: Endpoint) -> dict[str, Any]:
        """
        Async version of generate_payload that enables Tier 3 prefetching.

        When a DependencyPrefetcher is configured, this method will call
        the target API to harvest real foreign key values before generating
        the body payload.

        Args:
            endpoint: The Endpoint object to generate a payload for.

        Returns:
            Dict with keys: path_params, query_params, headers, body.
        """
        logger.info(
            "Generating payload (async) for %s %s",
            endpoint.method.value, endpoint.path,
        )

        # Generate parameters (path, query, header)
        path_params, query_params, headers = self._generate_parameters(endpoint)

        # Tier 3: Prefetch foreign key values if possible
        body: dict[str, Any] = {}
        if endpoint.request_body_schema:
            if self.prefetcher:
                self._prefetched_values = (
                    await self.prefetcher.prefetch_foreign_keys(
                        endpoint.request_body_schema
                    )
                )
                logger.info(
                    "Tier 3 prefetched %d foreign key values: %s",
                    len(self._prefetched_values),
                    list(self._prefetched_values.keys()),
                )
            body = self._generate_body(endpoint.request_body_schema)

        payload = {
            "path_params": path_params,
            "query_params": query_params,
            "headers": headers,
            "body": body,
        }

        logger.debug("Generated payload (async): %s", payload)
        return payload

    # ─────────────────────────────────────────
    # Parameter Generation
    # ─────────────────────────────────────────

    def _generate_parameters(
        self, endpoint: Endpoint
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        """
        Generate values for path parameters, query parameters, and headers
        from the endpoint's parameters list.

        Args:
            endpoint: The Endpoint whose parameters to generate.

        Returns:
            Tuple of (path_params, query_params, headers).
        """
        path_params: dict[str, Any] = {}
        query_params: dict[str, Any] = {}
        headers: dict[str, str] = {}

        for param in endpoint.parameters:
            if not isinstance(param, dict):
                continue

            name = param.get("name", "")
            location = param.get("in", "")
            schema = param.get("schema", {})

            if not name:
                continue

            value = self._resolve_value(name, schema)

            if location == "path":
                path_params[name] = value
            elif location == "query":
                query_params[name] = value
            elif location == "header":
                headers[name] = str(value)
            # 'cookie' params are intentionally skipped

        logger.debug(
            "Parameters → path: %s, query: %s, headers: %s",
            path_params, query_params, headers,
        )
        return path_params, query_params, headers

    # ─────────────────────────────────────────
    # Body Generation (Schema Walker)
    # ─────────────────────────────────────────

    def _generate_body(self, schema: dict[str, Any]) -> dict[str, Any]:
        """
        Generate the request body by walking the schema.

        Args:
            schema: The request body JSON schema.

        Returns:
            A fully populated dict matching the schema.
        """
        result = self._walk_schema(schema, "")
        if isinstance(result, dict):
            return result
        return {}

    def _walk_schema(
        self, schema: dict[str, Any], property_name: str = ""
    ) -> Any:
        """
        Recursively walk a JSON schema and produce a value for each node.

        Handles:
        - object with properties → dict
        - array with items → list with one generated item
        - allOf → merge all sub-schemas
        - oneOf / anyOf → pick first sub-schema
        - leaf types → resolve via three-tier system

        Args:
            schema: The JSON schema node to process.
            property_name: The property name for context (used by heuristics).

        Returns:
            The generated value: dict, list, string, int, float, or bool.
        """
        if not isinstance(schema, dict):
            return self._resolve_value(property_name, {})

        # Handle allOf: merge all sub-schemas into one object
        if "allOf" in schema:
            return self._handle_all_of(schema["allOf"], property_name)

        # Handle oneOf / anyOf: pick the first sub-schema
        for combiner in ("oneOf", "anyOf"):
            if combiner in schema:
                sub_schemas = schema[combiner]
                if isinstance(sub_schemas, list) and sub_schemas:
                    first = sub_schemas[0]
                    if isinstance(first, dict):
                        logger.debug(
                            "Schema %s: picking first from %s",
                            property_name, combiner,
                        )
                        return self._walk_schema(first, property_name)

        schema_type = schema.get("type", "object")

        # Handle object type
        if schema_type == "object" or "properties" in schema:
            return self._walk_object(schema, property_name)

        # Handle array type
        if schema_type == "array":
            return self._walk_array(schema, property_name)

        # Leaf type: resolve the value through the three-tier system
        return self._resolve_value(property_name, schema)

    def _walk_object(
        self, schema: dict[str, Any], property_name: str = ""
    ) -> dict[str, Any]:
        """
        Walk an object schema and generate a dict with values for each property.

        Args:
            schema: The object schema with a 'properties' dict.
            property_name: Parent property name for context.

        Returns:
            A dict with generated values for each property.
        """
        result: dict[str, Any] = {}
        properties = schema.get("properties", {})

        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue
            result[prop_name] = self._walk_schema(prop_schema, prop_name)

        # Handle additionalProperties if no explicit properties
        if not properties and "additionalProperties" in schema:
            additional = schema["additionalProperties"]
            if isinstance(additional, dict):
                result["key"] = self._walk_schema(additional, "key")

        return result

    def _walk_array(
        self, schema: dict[str, Any], property_name: str = ""
    ) -> list[Any]:
        """
        Walk an array schema and generate a list with one item.

        Args:
            schema: The array schema with an 'items' sub-schema.
            property_name: Parent property name for context.

        Returns:
            A list containing one generated item.
        """
        items_schema = schema.get("items", {})
        if isinstance(items_schema, dict):
            item = self._walk_schema(items_schema, property_name)
            return [item]
        return []

    def _handle_all_of(
        self, sub_schemas: list, property_name: str = ""
    ) -> dict[str, Any]:
        """
        Merge all sub-schemas from an allOf combiner into a single object.

        Args:
            sub_schemas: List of sub-schema dicts to merge.
            property_name: Parent property name for context.

        Returns:
            A merged dict from all sub-schemas.
        """
        merged: dict[str, Any] = {}

        for sub in sub_schemas:
            if not isinstance(sub, dict):
                continue
            result = self._walk_schema(sub, property_name)
            if isinstance(result, dict):
                merged.update(result)

        return merged

    # ─────────────────────────────────────────
    # Three-Tier Value Resolution
    # ─────────────────────────────────────────

    def _resolve_value(
        self, property_name: str, schema: dict[str, Any]
    ) -> Any:
        """
        Resolve a value for a single schema property using the three tiers.

        Priority:
        1. Tier 1: Spec-provided example/default values
        2. Tier 3: Dependency prefetch (if a prefetched value exists)
        3. Tier 2: Format and name heuristics

        Note: Tier 3 is checked before Tier 2 because prefetched IDs
        are more reliable than heuristic guesses for FK fields.

        Args:
            property_name: The name of the property (used for heuristics).
            schema: The JSON schema for this property.

        Returns:
            The resolved value.
        """
        # Tier 1: Spec examples / defaults
        tier1 = self._tier1_spec_examples(schema)
        if tier1 is not None:
            logger.debug(
                "Tier 1 (spec example) for '%s': %s", property_name, tier1
            )
            return tier1

        # Tier 3: Prefetched foreign key values
        if property_name in self._prefetched_values:
            value = self._prefetched_values[property_name]
            logger.debug(
                "Tier 3 (prefetch) for '%s': %s", property_name, value
            )
            return value

        # Tier 2: Format / name / type heuristics
        tier2 = self._tier2_heuristics(property_name, schema)
        logger.debug("Tier 2 (heuristic) for '%s': %s", property_name, tier2)
        return tier2

    # ─────────────────────────────────────────
    # Tier 1: Spec Examples
    # ─────────────────────────────────────────

    def _tier1_spec_examples(self, schema: dict[str, Any]) -> Any | None:
        """
        Extract example or default values from the schema.

        Checks in order: 'example', 'examples', 'default'.

        Args:
            schema: The property schema that may contain example values.

        Returns:
            The example value, or None if no examples are found.
        """
        if not isinstance(schema, dict):
            return None

        # Check 'example' (single value — most common)
        if "example" in schema:
            return schema["example"]

        # Check 'examples' (OAS 3.1 style — dict of named examples)
        examples = schema.get("examples")
        if isinstance(examples, dict) and examples:
            # Pick the first example's value
            first_example = next(iter(examples.values()))
            if isinstance(first_example, dict) and "value" in first_example:
                return first_example["value"]
            return first_example

        # Check 'examples' as a list (JSON Schema style)
        if isinstance(examples, list) and examples:
            return examples[0]

        # Check 'default'
        if "default" in schema:
            return schema["default"]

        return None

    # ─────────────────────────────────────────
    # Tier 2: Format & Name Heuristics
    # ─────────────────────────────────────────

    def _tier2_heuristics(
        self, property_name: str, schema: dict[str, Any]
    ) -> Any:
        """
        Generate a realistic value using format hints, property name patterns,
        type constraints, and enum values.

        Resolution order:
        1. Enum values (pick first)
        2. Format-based generation (email, date-time, uuid, etc.)
        3. Property name heuristics (name, phone, price, etc.)
        4. Type-based fallback (integer, number, boolean, string)

        Args:
            property_name: The property name for contextual heuristics.
            schema: The property schema with type/format/constraints.

        Returns:
            A generated value that should pass validation.
        """
        if not isinstance(schema, dict):
            schema = {}

        # 1. Enum: always pick from the enum array
        enum_values = schema.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return enum_values[0]

        schema_type = schema.get("type", "string")
        schema_format = schema.get("format", "")

        # 2. Format-based generation
        format_value = self._generate_by_format(schema_format, schema)
        if format_value is not None:
            return format_value

        # 3. Property name heuristics
        name_value = self._generate_by_name(property_name, schema_type, schema)
        if name_value is not None:
            return name_value

        # 4. Type-based fallback
        return self._generate_by_type(property_name, schema_type, schema)

    def _generate_by_format(
        self, fmt: str, schema: dict[str, Any]
    ) -> Any | None:
        """
        Generate a value based on the schema 'format' field.

        Args:
            fmt: The format string (e.g., "email", "date-time", "uuid").
            schema: The full property schema for constraint checking.

        Returns:
            A formatted value, or None if the format is not recognized.
        """
        if not fmt:
            return None

        fmt_lower = fmt.lower()

        if fmt_lower == "email":
            suffix = random.randint(1000, 9999)
            return f"user_{suffix}@example.com"

        if fmt_lower == "date-time":
            dt = datetime.now(timezone.utc) - timedelta(
                days=random.randint(0, 30)
            )
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if fmt_lower == "date":
            dt = datetime.now(timezone.utc) - timedelta(
                days=random.randint(0, 365)
            )
            return dt.strftime("%Y-%m-%d")

        if fmt_lower == "time":
            return f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00"

        if fmt_lower == "uuid":
            return str(uuid.uuid4())

        if fmt_lower in ("uri", "url"):
            return f"https://example.com/resource/{random.randint(1, 1000)}"

        if fmt_lower == "ipv4":
            return (
                f"{random.randint(10, 192)}.{random.randint(0, 255)}"
                f".{random.randint(0, 255)}.{random.randint(1, 254)}"
            )

        if fmt_lower == "ipv6":
            segments = [f"{random.randint(0, 0xFFFF):04x}" for _ in range(8)]
            return ":".join(segments)

        if fmt_lower == "hostname":
            return f"host-{random.randint(1, 999)}.example.com"

        if fmt_lower in ("int32", "int64"):
            return self._generate_integer(schema)

        if fmt_lower in ("float", "double"):
            return self._generate_number(schema)

        if fmt_lower == "byte":
            # Base64-encoded string
            import base64

            raw = f"test-data-{random.randint(100, 999)}"
            return base64.b64encode(raw.encode()).decode()

        if fmt_lower == "binary":
            return "binary-content-placeholder"

        if fmt_lower == "password":
            return f"Gh0$t_Pass!{random.randint(10, 99)}"

        return None

    def _generate_by_name(
        self, property_name: str, schema_type: str, schema: dict[str, Any]
    ) -> Any | None:
        """
        Generate a value based on property name pattern matching.

        Args:
            property_name: The property name to match against patterns.
            schema_type: The schema type (string, integer, etc.).
            schema: The full property schema for constraint checking.

        Returns:
            A contextual value, or None if no pattern matches.
        """
        if not property_name:
            return None

        for pattern, hint in _NAME_HEURISTICS:
            if pattern.search(property_name):
                return self._generate_from_hint(hint, schema_type, schema)

        return None

    def _generate_from_hint(
        self, hint: str, schema_type: str, schema: dict[str, Any]
    ) -> Any:
        """
        Generate a value from a semantic hint derived from name matching.

        Args:
            hint: The semantic hint (e.g., "email", "phone", "price").
            schema_type: The declared type for constraint respect.
            schema: The full schema for constraints.

        Returns:
            A generated value matching the hint.
        """
        if hint == "uuid":
            return str(uuid.uuid4())

        if hint == "email":
            return f"{random.choice(_FIRST_NAMES).lower()}@example.com"

        if hint == "password":
            return f"Gh0$t_Pass!{random.randint(10, 99)}"

        if hint == "phone":
            return f"+1-555-{random.randint(1000, 9999):04d}"

        if hint == "url":
            return f"https://example.com/{random.randint(1, 1000)}"

        if hint == "price":
            if schema_type == "integer":
                return self._generate_integer(schema)
            return round(random.uniform(9.99, 199.99), 2)

        if hint == "quantity":
            minimum = schema.get("minimum", 1)
            maximum = schema.get("maximum", 10)
            return random.randint(int(minimum), int(maximum))

        if hint == "description":
            return self._apply_string_constraints(_LOREM, schema)

        if hint == "first_name":
            return random.choice(_FIRST_NAMES)

        if hint == "last_name":
            return random.choice(_LAST_NAMES)

        if hint == "name":
            return random.choice(_FIRST_NAMES)

        if hint == "address":
            return f"{random.randint(100, 9999)} {random.choice(_LAST_NAMES)} Street"

        if hint == "city":
            return random.choice(_CITIES)

        if hint == "country":
            return random.choice(_COUNTRIES)

        if hint == "zip":
            return f"{random.randint(10000, 99999)}"

        if hint == "state":
            return random.choice(["CA", "NY", "TX", "FL", "WA", "IL"])

        if hint == "title":
            return f"Sample Title {random.randint(1, 100)}"

        if hint == "status":
            return random.choice(_STATUSES)

        if hint == "role":
            return random.choice(_ROLES)

        if hint == "rating":
            minimum = schema.get("minimum", 1)
            maximum = schema.get("maximum", 5)
            return random.randint(int(minimum), int(maximum))

        if hint == "age":
            return random.randint(18, 65)

        # Fallback
        return self._generate_by_type("", schema_type, schema)

    def _generate_by_type(
        self, property_name: str, schema_type: str, schema: dict[str, Any]
    ) -> Any:
        """
        Type-based fallback value generation.

        Args:
            property_name: The property name for last-resort context.
            schema_type: The JSON schema type string.
            schema: The full property schema for constraints.

        Returns:
            A value of the correct type.
        """
        if schema_type == "integer":
            return self._generate_integer(schema)

        if schema_type == "number":
            return self._generate_number(schema)

        if schema_type == "boolean":
            return True

        if schema_type == "string":
            return self._generate_string(property_name, schema)

        if schema_type == "array":
            return []

        if schema_type == "object":
            return {}

        # Null or unknown type
        if schema_type == "null":
            return None

        # Default: return a contextual string
        return self._generate_string(property_name, schema)

    # ─────────────────────────────────────────
    # Type-Specific Generators with Constraints
    # ─────────────────────────────────────────

    def _generate_integer(self, schema: dict[str, Any]) -> int:
        """
        Generate an integer respecting minimum/maximum constraints.

        Args:
            schema: The property schema with optional min/max.

        Returns:
            A valid integer within the constraints.
        """
        minimum = schema.get("minimum", 1)
        maximum = schema.get("maximum", 1000)

        # Handle exclusiveMinimum / exclusiveMaximum
        if schema.get("exclusiveMinimum") is not None:
            exclusive_min = schema["exclusiveMinimum"]
            if isinstance(exclusive_min, bool):
                # OAS 3.0 style: exclusiveMinimum is a boolean modifier
                if exclusive_min:
                    minimum = int(minimum) + 1
            else:
                # OAS 3.1 / JSON Schema style: exclusiveMinimum is a number
                minimum = int(exclusive_min) + 1

        if schema.get("exclusiveMaximum") is not None:
            exclusive_max = schema["exclusiveMaximum"]
            if isinstance(exclusive_max, bool):
                if exclusive_max:
                    maximum = int(maximum) - 1
            else:
                maximum = int(exclusive_max) - 1

        minimum = int(minimum)
        maximum = int(maximum)

        if minimum > maximum:
            minimum, maximum = maximum, minimum

        return random.randint(minimum, maximum)

    def _generate_number(self, schema: dict[str, Any]) -> float:
        """
        Generate a float respecting minimum/maximum constraints.

        Args:
            schema: The property schema with optional min/max.

        Returns:
            A valid float within the constraints, rounded to 2 decimals.
        """
        minimum = float(schema.get("minimum", 0.01))
        maximum = float(schema.get("maximum", 1000.0))

        if schema.get("exclusiveMinimum") is not None:
            exclusive_min = schema["exclusiveMinimum"]
            if isinstance(exclusive_min, (int, float)):
                minimum = exclusive_min + 0.01

        if schema.get("exclusiveMaximum") is not None:
            exclusive_max = schema["exclusiveMaximum"]
            if isinstance(exclusive_max, (int, float)):
                maximum = exclusive_max - 0.01

        if minimum > maximum:
            minimum, maximum = maximum, minimum

        return round(random.uniform(minimum, maximum), 2)

    def _generate_string(
        self, property_name: str, schema: dict[str, Any]
    ) -> str:
        """
        Generate a string value respecting constraints.

        Handles minLength, maxLength, and pattern constraints.

        Args:
            property_name: The property name for context.
            schema: The property schema with optional constraints.

        Returns:
            A valid string value.
        """
        # Handle pattern constraint
        pattern = schema.get("pattern")
        if pattern:
            generated = self._generate_from_pattern(pattern)
            if generated:
                return self._apply_string_constraints(generated, schema)

        # Build a contextual base string
        if property_name:
            base = f"test_{property_name}_{random.randint(100, 999)}"
        else:
            base = f"test_value_{random.randint(100, 999)}"

        return self._apply_string_constraints(base, schema)

    def _apply_string_constraints(
        self, value: str, schema: dict[str, Any]
    ) -> str:
        """
        Apply minLength and maxLength constraints to a string value.

        Args:
            value: The base string value.
            schema: The schema with optional length constraints.

        Returns:
            The adjusted string within length bounds.
        """
        min_length = schema.get("minLength", 0)
        max_length = schema.get("maxLength")

        # Pad if too short
        if len(value) < min_length:
            padding = "x" * (min_length - len(value))
            value = value + padding

        # Truncate if too long
        if max_length is not None and len(value) > max_length:
            value = value[:max_length]

        return value

    def _generate_from_pattern(self, pattern: str) -> str | None:
        """
        Attempt to generate a string matching a regex pattern.

        Handles common patterns used in API specs. Falls back to None
        for complex patterns that can't be easily reverse-generated.

        Args:
            pattern: The regex pattern string.

        Returns:
            A matching string, or None if the pattern is too complex.
        """
        # Common pattern: phone numbers like ^\\+?[0-9\\-\\s]+$
        if re.search(r"\\+.*0-9", pattern) or "phone" in pattern.lower():
            return f"+1-555-{random.randint(1000, 9999)}"

        # Email-like patterns
        if "@" in pattern or "email" in pattern.lower():
            return f"user_{random.randint(1000, 9999)}@example.com"

        # UUID patterns
        if re.search(r"\[0-9a-f\].*\{8\}", pattern, re.I):
            return str(uuid.uuid4())

        # Alphanumeric patterns like ^[a-zA-Z0-9]+$
        if re.search(r"\[a-z.*A-Z.*0-9\]", pattern):
            length = 8
            # Try to extract length from pattern
            length_match = re.search(r"\{(\d+)(?:,(\d+))?\}", pattern)
            if length_match:
                min_len = int(length_match.group(1))
                max_len = int(length_match.group(2) or min_len)
                length = random.randint(min_len, max_len)
            chars = string.ascii_letters + string.digits
            return "".join(random.choice(chars) for _ in range(length))

        # Simple character class patterns like ^[A-Z]{2,4}$
        length_match = re.search(r"\{(\d+)(?:,(\d+))?\}", pattern)
        if length_match:
            min_len = int(length_match.group(1))
            max_len = int(length_match.group(2) or min_len)
            length = random.randint(min_len, max_len)

            if "[A-Z]" in pattern or "[a-zA-Z]" in pattern:
                chars = string.ascii_uppercase
                return "".join(random.choice(chars) for _ in range(length))
            if "[0-9]" in pattern:
                return "".join(
                    str(random.randint(0, 9)) for _ in range(length)
                )

        # Can't handle complex patterns — return None so caller uses fallback
        return None
