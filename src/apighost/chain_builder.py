"""
APIGhost Chain Builder — Dual-Layer Producer-Consumer Resolution

The crown jewel of APIGhost. This module takes a fully resolved OpenAPI
specification (from parser.py) and automatically generates stateful
attack chains for cross-user BOLA testing.

Architecture:
    Layer 1 (Path-Based CRUD Grouping):
        Groups endpoints by RESTful base path. Fast, handles 80% of APIs.
        /api/orders (POST) + /api/orders/{id} (GET/DELETE) → AttackChain

    Layer 2 (Schema-Based Producer-Consumer Matching):
        For endpoints NOT matched by Layer 1. Scans POST response schemas
        for "producer" fields (IDs) and matches them against GET parameter
        schemas. Handles non-RESTful, messy APIs.

Output:
    A list of AttackChain objects, each representing:
        CREATE (User A) → READ (User B tests access) → DELETE (User A teardown)
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from apighost.models import (
    AttackChain,
    ChainSource,
    CrudRole,
    Endpoint,
    HttpMethod,
    ResourceGroup,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Path parameter regex
# ─────────────────────────────────────────────
PATH_PARAM_PATTERN = re.compile(r'\{([^}]+)\}')

# Common ID-like field name patterns for producer-consumer matching
ID_FIELD_PATTERNS = re.compile(
    r'(?:^id$|_id$|Id$|ID$|_uuid$|_key$|_token$|_ref$)',
    re.IGNORECASE
)


class ChainBuilder:
    """
    Dual-Layer Chain Resolution Engine.

    Takes a resolved OpenAPI spec dict and produces a list of AttackChain
    objects that the Executor can run with two user tokens.
    """

    def __init__(self, resolved_spec: dict[str, Any]):
        self.spec = resolved_spec
        self.endpoints: list[Endpoint] = []
        self.chains: list[AttackChain] = []
        self._chain_counter = 0

    def build_chains(self) -> list[AttackChain]:
        """
        Main entry point. Runs both layers and returns all discovered chains.

        Returns:
            List of AttackChain objects ready for execution.
        """
        # Step 1: Extract all endpoints from the resolved spec
        self._extract_endpoints()
        logger.info(f"Extracted {len(self.endpoints)} endpoints from spec.")

        if not self.endpoints:
            logger.warning("No endpoints found in spec. Nothing to chain.")
            return []

        # Step 2: Layer 1 — Path-Based CRUD Grouping
        layer1_chains, unmatched = self._layer1_path_grouping()
        logger.info(
            f"Layer 1 (Path-Based): Generated {len(layer1_chains)} chains, "
            f"{len(unmatched)} endpoints unmatched."
        )

        # Step 3: Layer 2 — Schema-Based Producer-Consumer Matching
        layer2_chains = self._layer2_schema_matching(unmatched)
        logger.info(
            f"Layer 2 (Schema-Based): Generated {len(layer2_chains)} chains."
        )

        # Combine results
        self.chains = layer1_chains + layer2_chains
        logger.info(f"Total attack chains discovered: {len(self.chains)}")

        return self.chains

    # ─────────────────────────────────────────
    # Step 1: Endpoint Extraction
    # ─────────────────────────────────────────

    def _extract_endpoints(self) -> None:
        """
        Parse the resolved spec and create Endpoint objects for every
        path + method combination.
        """
        paths = self.spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method_str, details in methods.items():
                method_str_upper = method_str.upper()

                # Skip non-HTTP-method keys like "parameters", "summary", etc.
                if method_str_upper not in {m.value for m in HttpMethod}:
                    continue

                if not isinstance(details, dict):
                    continue

                method = HttpMethod(method_str_upper)

                # Extract path parameter names
                path_params = PATH_PARAM_PATTERN.findall(path)
                has_path_params = len(path_params) > 0

                # Extract parameters (path, query, header, cookie)
                parameters = details.get("parameters", [])
                # Also inherit path-level parameters
                path_level_params = methods.get("parameters", [])
                if isinstance(path_level_params, list):
                    parameters = path_level_params + parameters

                # Extract request body schema (for POST/PUT/PATCH)
                request_body_schema = self._extract_request_body_schema(details)

                # Extract success response schema (200 or 201)
                response_schema = self._extract_response_schema(details)

                endpoint = Endpoint(
                    path=path,
                    method=method,
                    operation_id=details.get("operationId"),
                    summary=details.get("summary"),
                    parameters=parameters if isinstance(parameters, list) else [],
                    request_body_schema=request_body_schema,
                    response_schema=response_schema,
                    has_path_params=has_path_params,
                    path_param_names=path_params,
                )

                self.endpoints.append(endpoint)

    def _extract_request_body_schema(self, details: dict) -> dict[str, Any] | None:
        """Extract the JSON request body schema from an operation."""
        request_body = details.get("requestBody", {})
        if not isinstance(request_body, dict):
            return None

        content = request_body.get("content", {})
        # Prefer application/json
        json_content = content.get("application/json", {})
        if not json_content:
            # Fall back to first available content type
            for ct, ct_schema in content.items():
                if "json" in ct.lower():
                    json_content = ct_schema
                    break

        if isinstance(json_content, dict):
            return json_content.get("schema")
        return None

    def _extract_response_schema(self, details: dict) -> dict[str, Any] | None:
        """Extract the JSON response schema from 200 or 201 responses."""
        responses = details.get("responses", {})
        if not isinstance(responses, dict):
            return None

        # Try 201 first (common for POST create), then 200
        for status_code in ["201", "200", 201, 200]:
            response = responses.get(status_code)
            if not isinstance(response, dict):
                continue

            content = response.get("content", {})
            json_content = content.get("application/json", {})

            if not json_content:
                for ct, ct_schema in content.items():
                    if "json" in ct.lower():
                        json_content = ct_schema
                        break

            if isinstance(json_content, dict):
                schema = json_content.get("schema")
                if schema:
                    return schema

        return None

    # ─────────────────────────────────────────
    # Layer 1: Path-Based CRUD Grouping
    # ─────────────────────────────────────────

    def _layer1_path_grouping(self) -> tuple[list[AttackChain], list[Endpoint]]:
        """
        Group endpoints by their base path and identify CRUD operations.

        Example:
            POST   /api/orders          → CREATE
            GET    /api/orders/{id}      → READ
            DELETE /api/orders/{id}      → DELETE (teardown)

        Returns:
            Tuple of (chains generated, endpoints that couldn't be matched)
        """
        # Group endpoints by base_path
        groups: dict[str, ResourceGroup] = defaultdict(
            lambda: ResourceGroup(base_path="")
        )

        for ep in self.endpoints:
            base = ep.base_path
            if groups[base].base_path == "":
                groups[base] = ResourceGroup(base_path=base)
            groups[base].endpoints.append(ep)

        chains: list[AttackChain] = []
        matched_endpoints: set[int] = set()  # Track matched endpoint indices

        for base_path, group in groups.items():
            if not group.can_form_chain:
                continue

            create_ep = group.create_endpoint
            read_ep = group.read_endpoint
            delete_ep = group.delete_endpoint

            # Determine the ID field that links CREATE response to READ path param
            id_field = self._infer_id_field(create_ep, read_ep)

            # Extract a human-readable resource name from the path
            resource_name = self._extract_resource_name(base_path)

            chain = AttackChain(
                chain_id=self._next_chain_id(),
                resource_name=resource_name,
                source=ChainSource.LAYER1_PATH,
                create=create_ep,
                read=read_ep,
                delete=delete_ep,
                id_field=id_field,
                confidence=0.95,  # High confidence for RESTful path matching
            )

            chains.append(chain)

            # Mark these endpoints as matched
            for ep in group.endpoints:
                idx = self.endpoints.index(ep)
                matched_endpoints.add(idx)

            logger.debug(f"Layer 1 chain: {chain}")

        # Return unmatched endpoints for Layer 2
        unmatched = [
            ep for i, ep in enumerate(self.endpoints)
            if i not in matched_endpoints
        ]

        return chains, unmatched

    # ─────────────────────────────────────────
    # Layer 2: Schema-Based Producer-Consumer
    # ─────────────────────────────────────────

    def _layer2_schema_matching(
        self, unmatched: list[Endpoint]
    ) -> list[AttackChain]:
        """
        For endpoints not matched by Layer 1, scan response schemas for
        "producer" fields and match them against "consumer" parameters.

        Producer: A POST endpoint whose response contains ID-like fields.
        Consumer: A GET/DELETE endpoint whose path/query params accept those IDs.

        Example:
            POST /api/create-order  → response: {"order_id": 42}
            GET  /api/fetch-order?order_id=42
            → "order_id" in POST response matches "order_id" in GET params
            → Link them as a chain.
        """
        chains: list[AttackChain] = []

        # Separate producers (POST endpoints) and consumers (GET/DELETE)
        producers = [
            ep for ep in unmatched
            if ep.method == HttpMethod.POST and ep.response_schema
        ]
        consumers = [
            ep for ep in unmatched
            if ep.method in (HttpMethod.GET, HttpMethod.DELETE)
        ]

        if not producers or not consumers:
            return chains

        for producer in producers:
            # Extract all ID-like fields from the producer's response schema
            produced_fields = self._extract_id_fields_from_schema(
                producer.response_schema
            )

            if not produced_fields:
                continue

            # Find consumers that accept any of these fields
            best_match: Endpoint | None = None
            best_field: str | None = None
            best_score: float = 0.0
            best_delete: Endpoint | None = None

            for consumer in consumers:
                consumed_params = self._extract_consumed_params(consumer)

                # Find overlapping field names
                for p_field in produced_fields:
                    for c_param in consumed_params:
                        score = self._field_match_score(p_field, c_param)
                        if score > best_score and consumer.method == HttpMethod.GET:
                            best_score = score
                            best_match = consumer
                            best_field = p_field

                        # Also check if any DELETE consumer matches
                        if score > 0.5 and consumer.method == HttpMethod.DELETE:
                            best_delete = consumer

            if best_match and best_field and best_score >= 0.5:
                resource_name = self._extract_resource_name(producer.path)

                chain = AttackChain(
                    chain_id=self._next_chain_id(),
                    resource_name=resource_name,
                    source=ChainSource.LAYER2_SCHEMA,
                    create=producer,
                    read=best_match,
                    delete=best_delete,
                    id_field=best_field,
                    confidence=best_score,
                )

                chains.append(chain)
                logger.debug(f"Layer 2 chain: {chain}")

        return chains

    def _extract_id_fields_from_schema(
        self, schema: dict[str, Any] | None
    ) -> list[str]:
        """
        Recursively scan a JSON schema and extract field names that look
        like identifiers (id, order_id, uuid, etc.).
        """
        if not schema:
            return []

        id_fields: list[str] = []

        # Handle object schemas
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for field_name, field_schema in properties.items():
                if not isinstance(field_schema, dict):
                    continue

                # Check if the field name matches ID patterns
                if ID_FIELD_PATTERNS.search(field_name):
                    id_fields.append(field_name)
                    continue

                # Check if the field type is integer/string with "id" in the name
                field_type = field_schema.get("type", "")
                if field_type in ("integer", "string") and "id" in field_name.lower():
                    id_fields.append(field_name)

        # Handle array schemas (e.g., response is a list of items)
        items = schema.get("items")
        if isinstance(items, dict):
            id_fields.extend(self._extract_id_fields_from_schema(items))

        # Handle allOf / oneOf / anyOf
        for combiner in ("allOf", "oneOf", "anyOf"):
            sub_schemas = schema.get(combiner, [])
            if isinstance(sub_schemas, list):
                for sub in sub_schemas:
                    if isinstance(sub, dict):
                        id_fields.extend(
                            self._extract_id_fields_from_schema(sub)
                        )

        return id_fields

    def _extract_consumed_params(self, endpoint: Endpoint) -> list[str]:
        """
        Extract all parameter names that a consumer endpoint accepts.
        This includes path params, query params, and request body fields.
        """
        params: list[str] = []

        # Path parameters from the URL
        params.extend(endpoint.path_param_names)

        # Query/path/header parameters from the spec
        for param in endpoint.parameters:
            if isinstance(param, dict):
                name = param.get("name", "")
                location = param.get("in", "")
                if location in ("path", "query") and name:
                    params.append(name)

        return params

    def _field_match_score(self, producer_field: str, consumer_param: str) -> float:
        """
        Score how well a producer field matches a consumer parameter.

        Exact match:     "order_id" == "order_id"       → 1.0
        Case-insensitive: "orderId" vs "order_id"       → 0.8
        Substring match: "id" in "order_id"             → 0.6
        No match:                                       → 0.0
        """
        # Normalize: lowercase and strip underscores
        p_norm = producer_field.lower().replace("_", "").replace("-", "")
        c_norm = consumer_param.lower().replace("_", "").replace("-", "")

        # Exact match (case-insensitive, ignoring separators)
        if p_norm == c_norm:
            return 1.0

        # One is a suffix of the other (e.g., "id" matches "order_id")
        if p_norm.endswith(c_norm) or c_norm.endswith(p_norm):
            return 0.7

        # Substring match
        if p_norm in c_norm or c_norm in p_norm:
            return 0.6

        return 0.0

    # ─────────────────────────────────────────
    # Utility methods
    # ─────────────────────────────────────────

    def _infer_id_field(
        self, create_ep: Endpoint, read_ep: Endpoint
    ) -> str:
        """
        Infer the ID field name that links a CREATE response to a READ parameter.

        Priority:
        1. If READ has a path param, use that name (e.g., "id" from /orders/{id}).
        2. If CREATE has a response schema with ID-like fields, use the first match.
        3. Default to "id".
        """
        # Priority 1: Path param from the READ endpoint
        if read_ep.path_param_names:
            return read_ep.path_param_names[-1]  # Last param is usually the resource ID

        # Priority 2: ID fields from CREATE response schema
        if create_ep.response_schema:
            id_fields = self._extract_id_fields_from_schema(
                create_ep.response_schema
            )
            if id_fields:
                return id_fields[0]

        # Priority 3: Fallback
        return "id"

    def _extract_resource_name(self, path: str) -> str:
        """
        Extract a human-readable resource name from an API path.

        /api/v1/orders/{id}     → orders
        /api/create-order       → create-order
        /users/{uid}/posts      → posts
        """
        # Remove version prefixes
        clean = re.sub(r'^/?(api/?)?(v\d+/?)?', '', path)
        # Split by / and get the last meaningful segment
        segments = [s for s in clean.split('/') if s and not s.startswith('{')]
        return segments[-1] if segments else path.strip('/')

    def _next_chain_id(self) -> str:
        """Generate a sequential chain ID."""
        self._chain_counter += 1
        return f"CHAIN_{self._chain_counter:03d}"


# ─────────────────────────────────────────────
# Convenience function
# ─────────────────────────────────────────────

def build_chains_from_spec(resolved_spec: dict[str, Any]) -> list[AttackChain]:
    """
    One-liner convenience function.

    Usage:
        from apighost.parser import SpecParser
        from apighost.chain_builder import build_chains_from_spec

        spec = SpecParser("openapi.yaml").parse()
        chains = build_chains_from_spec(spec)
    """
    builder = ChainBuilder(resolved_spec)
    return builder.build_chains()
