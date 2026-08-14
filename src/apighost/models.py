"""
APIGhost Data Models

Core data structures used across the entire pipeline:
Spec Parser → Chain Builder → Data Generator → Executor → Verdict Engine
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class HttpMethod(enum.Enum):
    """Standard HTTP methods mapped to CRUD semantics."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class CrudRole(enum.Enum):
    """The CRUD role an endpoint plays in an attack chain."""
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    LIST = "LIST"
    UNKNOWN = "UNKNOWN"


class Verdict(enum.Enum):
    """Confidence levels for BOLA detection."""
    CONFIRMED = "CONFIRMED"   # Score >= 0.75 — BOLA is proven
    LIKELY = "LIKELY"         # Score >= 0.50 — strong signal, needs manual check
    POSSIBLE = "POSSIBLE"     # Score >= 0.25 — weak signal, likely false positive
    SECURE = "SECURE"         # Score < 0.25 — no BOLA detected
    ERROR = "ERROR"           # Server returned 5xx — inconclusive


class ChainSource(enum.Enum):
    """Which layer of the Chain Builder generated this chain."""
    LAYER1_PATH = "LAYER1_PATH"       # Path-based CRUD grouping
    LAYER2_SCHEMA = "LAYER2_SCHEMA"   # Schema-based producer-consumer matching
    BFLA_HEURISTIC = "BFLA_HEURISTIC" # BFLA privileged endpoints


class AuthMode(enum.Enum):
    """Supported authentication modes."""
    BEARER = "bearer"        # Authorization: Bearer <token>
    API_KEY = "api_key"      # Custom header: X-API-Key: <token>
    COOKIE = "cookie"        # Cookie: <name>=<token>
    BASIC = "basic"          # Authorization: Basic base64(user:pass)
    CUSTOM = "custom"        # User-defined header: <name>: <token>


class ChainVariant(enum.Enum):
    """The type of BOLA test this chain performs."""
    READ = "READ"       # Attacker reads owner's resource (data leak)
    UPDATE = "UPDATE"   # Attacker modifies owner's resource (data corruption)
    DELETE = "DELETE"   # Attacker deletes owner's resource (data destruction)
    BFLA = "BFLA"       # Attacker tries to access admin endpoint
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT" # Attacker attempts to modify restricted fields
    EXCESSIVE_DATA = "EXCESSIVE_DATA"
    RATE_LIMIT = "RATE_LIMIT"
    INJECTION = "INJECTION"


# ─────────────────────────────────────────────
# Spec Parser output
# ─────────────────────────────────────────────

@dataclass
class Endpoint:
    """A single API endpoint extracted from the resolved OpenAPI spec."""
    path: str                          # e.g., "/api/orders/{id}"
    method: HttpMethod                 # e.g., HttpMethod.GET
    operation_id: str | None = None    # e.g., "getOrderById"
    summary: str | None = None         # Human-readable summary from spec
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None  # 200/201 response schema
    has_path_params: bool = False      # True if path contains {param}
    path_param_names: list[str] = field(default_factory=list)  # e.g., ["id"]
    tags: list[str] = field(default_factory=list)      # OpenAPI tags

    @property
    def base_path(self) -> str:
        """
        Strip path parameters to get the base resource path.
        /api/orders/{id}       → /api/orders
        /api/users/{uid}/posts → /api/users/{uid}/posts  (keeps intermediate params)
        /api/orders/{order_id} → /api/orders
        """
        import re
        # Remove trailing path parameter segment(s)
        # /api/orders/{id} → /api/orders
        # /api/orders/{order_id}/items/{item_id} → /api/orders/{order_id}/items
        stripped = re.sub(r'/\{[^}]+\}$', '', self.path)
        return stripped if stripped else self.path

    @property
    def crud_role(self) -> CrudRole:
        """
        Infer the CRUD role based on HTTP method and path structure.

        Rules:
        - POST without path params → CREATE
        - GET with path params    → READ
        - GET without path params → LIST
        - PUT/PATCH with params   → UPDATE
        - DELETE with params      → DELETE
        """
        match self.method:
            case HttpMethod.POST:
                return CrudRole.CREATE
            case HttpMethod.GET:
                return CrudRole.READ if self.has_path_params else CrudRole.LIST
            case HttpMethod.PUT | HttpMethod.PATCH:
                return CrudRole.UPDATE if self.has_path_params else CrudRole.UNKNOWN
            case HttpMethod.DELETE:
                return CrudRole.DELETE if self.has_path_params else CrudRole.UNKNOWN
            case _:
                return CrudRole.UNKNOWN


# ─────────────────────────────────────────────
# Chain Builder output
# ─────────────────────────────────────────────

@dataclass
class ResourceGroup:
    """
    A group of endpoints that operate on the same REST resource.
    Generated by Layer 1 (path-based grouping).
    """
    base_path: str                     # e.g., "/api/orders"
    endpoints: list[Endpoint] = field(default_factory=list)

    @property
    def create_endpoint(self) -> Endpoint | None:
        """Find the POST (CREATE) endpoint in this group."""
        for ep in self.endpoints:
            if ep.crud_role == CrudRole.CREATE:
                return ep
        return None

    @property
    def read_endpoint(self) -> Endpoint | None:
        """Find the GET with path param (READ) endpoint."""
        for ep in self.endpoints:
            if ep.crud_role == CrudRole.READ:
                return ep
        return None

    @property
    def delete_endpoint(self) -> Endpoint | None:
        """Find the DELETE endpoint for teardown."""
        for ep in self.endpoints:
            if ep.crud_role == CrudRole.DELETE:
                return ep
        return None

    @property
    def update_endpoint(self) -> Endpoint | None:
        """Find the PUT/PATCH (UPDATE) endpoint in this group."""
        for ep in self.endpoints:
            if ep.crud_role == CrudRole.UPDATE:
                return ep
        return None

    @property
    def can_form_chain(self) -> bool:
        """A chain requires at minimum a CREATE and a READ endpoint."""
        return self.create_endpoint is not None and self.read_endpoint is not None


@dataclass
class AttackChain:
    """
    A complete stateful attack chain: CREATE → TEST → TEARDOWN.

    This is the core output of the Chain Builder. The Executor will
    run each chain with two tokens (User A creates, User B reads).
    """
    chain_id: str                      # Unique identifier, e.g., "chain_001"
    resource_name: str                  # Human-readable, e.g., "orders"
    source: ChainSource                # Which layer generated this chain

    # The three phases
    create: Endpoint                   # POST endpoint (User A creates a resource)
    read: Endpoint                     # GET endpoint (User B attempts to read it)
    delete: Endpoint | None = None     # DELETE endpoint (User A cleans up — optional)
    attack: Endpoint | None = None     # The endpoint the attacker uses (UPDATE/DELETE)

    # The linking fields between CREATE response and READ parameters
    id_fields: list[str] = field(default_factory=lambda: ["id"])
    
    variant: ChainVariant = ChainVariant.READ  # What the attacker does

    # Confidence that this chain is valid (0.0 to 1.0)
    confidence: float = 1.0

    def __str__(self) -> str:
        teardown = f" → DELETE {self.delete.path}" if self.delete else ""
        attack_str = f" → {self.attack.method.value} {self.attack.path} (ATTACK)" if self.attack else ""
        
        # If it's not a READ variant, the chain flow is slightly different
        if self.variant == ChainVariant.READ:
            return (
                f"[{self.chain_id}] {self.resource_name} "
                f"(via {self.source.value}, {self.variant.value})\n"
                f"  POST {self.create.path} → GET {self.read.path}{teardown}"
            )
        else:
            return (
                f"[{self.chain_id}] {self.resource_name} "
                f"(via {self.source.value}, {self.variant.value})\n"
                f"  POST {self.create.path} → GET {self.read.path}{attack_str}{teardown}"
            )


# ─────────────────────────────────────────────
# Executor models
# ─────────────────────────────────────────────

@dataclass
class ChainResult:
    """The result of executing a single attack chain."""
    chain: AttackChain
    verdict: Verdict = Verdict.SECURE
    score: float = 0.0

    # Response data for evidence
    create_status: int = 0
    create_body: dict[str, Any] = field(default_factory=dict)
    resource_ids: dict[str, Any] = field(default_factory=dict)

    read_as_owner_status: int = 0      # User A reads their own resource (baseline)
    read_as_owner_body: dict[str, Any] = field(default_factory=dict)

    read_as_attacker_status: int = 0   # User B reads User A's resource (attack)
    read_as_attacker_body: dict[str, Any] = field(default_factory=dict)

    teardown_status: int = 0
    teardown_success: bool = False

    # Signal breakdown for the report
    signals: dict[str, float] = field(default_factory=dict)

    error: str | None = None           # If the chain failed to execute
    duration_ms: int = 0

    def __str__(self) -> str:
        return (
            f"[{self.chain.chain_id}] {self.verdict.value} "
            f"(score: {self.score:.2f}) — {self.chain.resource_name}"
        )
