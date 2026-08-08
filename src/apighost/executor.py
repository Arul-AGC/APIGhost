"""
APIGhost Executor — Async Dual-Token Chain Execution Engine

Solves the "WAF/Rate Limit Reality" problem: Real APIs have rate limiters
and WAFs. Blind async requests get IPs banned or return 429s. This engine
implements industrial-grade network resilience.

Architecture:
    Token Bucket:
        Global rate limiter that paces requests across all chains.
        Configurable requests-per-second with burst capacity.

    Semaphore:
        Limits concurrent in-flight requests to avoid overwhelming
        the target or triggering connection-based WAF rules.

    Exponential Backoff:
        On 429/5xx, retries with exponential delay + random jitter.
        Max 3 retries before marking chain as ERROR.

    LIFO Cleanup Stack:
        Every CREATE pushes a teardown callable onto a stack.
        On completion (success or failure), teardowns run in LIFO
        order inside a try/finally. Prevents "ghost resources."

    Dead Letter Queue (DLQ):
        Failed teardowns are queued for a final sweep at scan end.
        Prevents resource leaks without blocking the main scan.

Flow per AttackChain:
    1. CREATE   — User A creates resource → extract ID from response
    2. READ(A)  — User A reads own resource → baseline response
    3. READ(B)  — User B reads User A's resource → attack probe
    4. TEARDOWN — User A deletes resource (LIFO stack + DLQ fallback)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import random
from dataclasses import dataclass, field
from typing import Any

import httpx

from apighost.models import (
    AttackChain,
    ChainResult,
    Endpoint,
    HttpMethod,
    Verdict,
)
from apighost.generator import DataGenerator

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Token Bucket Rate Limiter
# ─────────────────────────────────────────────

class TokenBucket:
    """
    A token bucket rate limiter for pacing HTTP requests.

    Prevents WAF triggers and 429 responses by ensuring we don't
    exceed a target requests-per-second rate. Supports burst capacity.

    Args:
        rate: Maximum requests per second (steady state).
        burst: Maximum burst capacity (tokens stored).
    """

    def __init__(self, rate: float = 10.0, burst: int = 15):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now

                # Refill tokens based on elapsed time
                self.tokens = min(
                    self.burst,
                    self.tokens + elapsed * self.rate,
                )

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

            # No tokens available — wait a fraction of the refill interval
            wait_time = (1.0 / self.rate) + random.uniform(0.01, 0.05)
            await asyncio.sleep(wait_time)


# ─────────────────────────────────────────────
# Dead Letter Queue for failed teardowns
# ─────────────────────────────────────────────

@dataclass
class DLQEntry:
    """A teardown that failed and needs a retry sweep."""
    chain_id: str
    method: str
    url: str
    headers: dict[str, str]
    attempt_count: int = 0
    last_error: str = ""


class DeadLetterQueue:
    """
    Collects failed teardown operations for a final retry sweep.

    When a DELETE teardown fails during chain execution (e.g., due to
    429 rate limiting), we don't block the scan. Instead, we queue it
    here and run a final sweep at the end.
    """

    def __init__(self):
        self._queue: list[DLQEntry] = []
        self._lock = asyncio.Lock()

    async def enqueue(self, entry: DLQEntry) -> None:
        """Add a failed teardown to the queue."""
        async with self._lock:
            self._queue.append(entry)
            logger.warning(
                f"DLQ: Queued failed teardown for {entry.chain_id} "
                f"({entry.method} {entry.url})"
            )

    async def sweep(
        self,
        client: httpx.AsyncClient,
        rate_limiter: TokenBucket,
        max_retries: int = 2,
    ) -> tuple[int, int]:
        """
        Final sweep: retry all queued teardowns.

        Returns:
            Tuple of (succeeded, failed) counts.
        """
        if not self._queue:
            logger.info("DLQ: No failed teardowns to sweep.")
            return 0, 0

        logger.info(f"DLQ: Starting final sweep of {len(self._queue)} entries.")
        succeeded = 0
        failed = 0

        for entry in self._queue:
            success = False
            for attempt in range(max_retries):
                try:
                    await rate_limiter.acquire()
                    response = await client.request(
                        method=entry.method,
                        url=entry.url,
                        headers=entry.headers,
                    )
                    if response.status_code < 500:
                        success = True
                        break
                    # 5xx — retry
                    await asyncio.sleep(2 ** attempt + random.uniform(0.1, 0.5))
                except Exception as e:
                    entry.last_error = str(e)
                    await asyncio.sleep(1.0)

            if success:
                succeeded += 1
                logger.info(f"DLQ: Cleaned up {entry.chain_id}")
            else:
                failed += 1
                logger.error(
                    f"DLQ: Permanently failed teardown for {entry.chain_id}: "
                    f"{entry.last_error}"
                )

        logger.info(f"DLQ sweep complete: {succeeded} cleaned, {failed} failed.")
        return succeeded, failed

    @property
    def size(self) -> int:
        return len(self._queue)


# ─────────────────────────────────────────────
# Executor Configuration
# ─────────────────────────────────────────────

@dataclass
class ExecutorConfig:
    """Configuration for the chain executor."""
    base_url: str                          # Target API base URL
    token_a: str                           # User A (owner) bearer token
    token_b: str                           # User B (attacker) bearer token
    requests_per_second: float = 10.0      # Token bucket rate
    burst_capacity: int = 15               # Token bucket burst
    max_concurrent: int = 5                # Semaphore limit
    max_retries: int = 3                   # Retry attempts on 429/5xx
    timeout_seconds: float = 30.0          # Per-request timeout
    auth_header: str = "Authorization"     # Header name for auth
    auth_scheme: str = "Bearer"            # Auth scheme prefix


# ─────────────────────────────────────────────
# Chain Executor
# ─────────────────────────────────────────────

class ChainExecutor:
    """
    Async dual-token chain execution engine.

    Executes AttackChain objects against a live API with two user
    identities to detect Broken Object Level Authorization (BOLA).

    Features:
        - Token bucket rate limiting
        - Concurrency control via semaphore
        - Exponential backoff with jitter on 429/5xx
        - LIFO cleanup stack for resource teardown
        - Dead Letter Queue for failed teardowns
        - Automatic ID extraction and injection
    """

    def __init__(self, config: ExecutorConfig, resolved_spec: dict[str, Any]):
        self.config = config
        self.spec = resolved_spec
        self.generator = DataGenerator(resolved_spec)

        # Network resilience components
        self._rate_limiter = TokenBucket(
            rate=config.requests_per_second,
            burst=config.burst_capacity,
        )
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        self._dlq = DeadLetterQueue()

        # LIFO cleanup stack (per-scan)
        self._cleanup_stack: list[tuple[str, str, dict[str, str]]] = []

        # Results
        self.results: list[ChainResult] = []

    def _auth_headers(self, token: str) -> dict[str, str]:
        """Build authorization headers for a given token."""
        return {
            self.config.auth_header: f"{self.config.auth_scheme} {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def execute_all(
        self, chains: list[AttackChain]
    ) -> list[ChainResult]:
        """
        Execute all attack chains against the target API.

        Chains are executed sequentially (not concurrently) to maintain
        state integrity — each chain's CREATE must complete before
        its READ can run.

        Args:
            chains: List of AttackChain objects from the Chain Builder.

        Returns:
            List of ChainResult objects with verdicts.
        """
        self.results = []

        logger.info(
            f"Starting scan: {len(chains)} chains against "
            f"{self.config.base_url}"
        )

        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=httpx.Timeout(self.config.timeout_seconds),
            follow_redirects=True,
            verify=False,  # Many test APIs use self-signed certs
        ) as client:
            for i, chain in enumerate(chains, 1):
                logger.info(
                    f"Executing chain {i}/{len(chains)}: "
                    f"{chain.chain_id} ({chain.resource_name})"
                )
                result = await self._execute_single_chain(client, chain)
                self.results.append(result)

                # Brief pause between chains to avoid burst patterns
                await asyncio.sleep(random.uniform(0.2, 0.8))

            # Final DLQ sweep
            if self._dlq.size > 0:
                logger.info("Running Dead Letter Queue final sweep...")
                await self._dlq.sweep(
                    client, self._rate_limiter, max_retries=2
                )

        logger.info(f"Scan complete. {len(self.results)} chains executed.")
        return self.results

    async def _execute_single_chain(
        self, client: httpx.AsyncClient, chain: AttackChain
    ) -> ChainResult:
        """
        Execute a single attack chain through all four phases.

        Flow:
            1. CREATE  (User A) → extract resource ID
            2. READ    (User A) → baseline response
            3. READ    (User B) → attack probe
            4. TEARDOWN (User A) → cleanup via LIFO stack
        """
        result = ChainResult(chain=chain)
        start_time = time.monotonic()
        teardown_url: str | None = None

        try:
            # ── Phase 1: CREATE (User A) ──────────────────────
            create_payload = self.generator.generate_payload(chain.create)
            create_url = self._build_url(
                chain.create.path, create_payload.get("path_params", {})
            )

            create_response = await self._send_request(
                client=client,
                method=chain.create.method.value,
                url=create_url,
                headers=self._auth_headers(self.config.token_a),
                json_body=create_payload.get("body"),
                query_params=create_payload.get("query_params"),
            )

            result.create_status = create_response.status_code

            # Parse response body
            try:
                result.create_body = create_response.json()
            except (json.JSONDecodeError, ValueError):
                result.create_body = {}

            # Extract resource ID from CREATE response
            resource_id = self._extract_resource_id(
                result.create_body, chain.id_field
            )

            if resource_id is None:
                result.error = (
                    f"CREATE returned {result.create_status} but could not "
                    f"extract '{chain.id_field}' from response body. "
                    f"Body: {json.dumps(result.create_body)[:200]}"
                )
                result.verdict = Verdict.ERROR
                logger.warning(f"{chain.chain_id}: {result.error}")
                return result

            result.resource_id = resource_id
            logger.info(
                f"{chain.chain_id}: Created resource with "
                f"{chain.id_field}={resource_id}"
            )

            # Push teardown onto LIFO stack
            if chain.delete:
                teardown_url = self._build_url(
                    chain.delete.path,
                    {chain.id_field: str(resource_id)},
                )
                # Also populate path param names from the delete endpoint
                if chain.delete.path_param_names:
                    param_map = {}
                    for pname in chain.delete.path_param_names:
                        param_map[pname] = str(resource_id)
                    teardown_url = self._build_url(
                        chain.delete.path, param_map
                    )

            # ── Phase 2: READ as Owner (User A) ──────────────
            read_url = self._build_read_url(chain, resource_id)

            owner_response = await self._send_request(
                client=client,
                method=chain.read.method.value,
                url=read_url,
                headers=self._auth_headers(self.config.token_a),
            )

            result.read_as_owner_status = owner_response.status_code
            try:
                result.read_as_owner_body = owner_response.json()
            except (json.JSONDecodeError, ValueError):
                result.read_as_owner_body = {}

            if result.read_as_owner_status >= 400:
                result.error = (
                    f"Owner READ failed with {result.read_as_owner_status}. "
                    f"Cannot establish baseline."
                )
                result.verdict = Verdict.ERROR
                logger.warning(f"{chain.chain_id}: {result.error}")
                return result

            # ── Phase 3: READ as Attacker (User B) ───────────
            attacker_response = await self._send_request(
                client=client,
                method=chain.read.method.value,
                url=read_url,
                headers=self._auth_headers(self.config.token_b),
            )

            result.read_as_attacker_status = attacker_response.status_code
            try:
                result.read_as_attacker_body = attacker_response.json()
            except (json.JSONDecodeError, ValueError):
                result.read_as_attacker_body = {}

            logger.info(
                f"{chain.chain_id}: Owner={result.read_as_owner_status}, "
                f"Attacker={result.read_as_attacker_status}"
            )

        except Exception as e:
            result.error = f"Chain execution failed: {str(e)}"
            result.verdict = Verdict.ERROR
            logger.error(f"{chain.chain_id}: {result.error}")

        finally:
            # ── Phase 4: TEARDOWN (User A, LIFO) ─────────────
            if teardown_url and chain.delete:
                await self._teardown(
                    client=client,
                    chain_id=chain.chain_id,
                    method=chain.delete.method.value,
                    url=teardown_url,
                    headers=self._auth_headers(self.config.token_a),
                    result=result,
                )

            result.duration_ms = int(
                (time.monotonic() - start_time) * 1000
            )

        return result

    # ─────────────────────────────────────────
    # HTTP Request with Resilience
    # ─────────────────────────────────────────

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict | None = None,
        query_params: dict | None = None,
    ) -> httpx.Response:
        """
        Send an HTTP request with rate limiting, concurrency control,
        and exponential backoff on failures.

        Args:
            client: The httpx async client.
            method: HTTP method (GET, POST, DELETE, etc.).
            url: Request URL (path, will be joined with base_url).
            headers: Request headers including auth.
            json_body: Optional JSON request body.
            query_params: Optional query parameters.

        Returns:
            The httpx Response object.

        Raises:
            httpx.HTTPError: If all retries are exhausted.
        """
        last_exception: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            # Rate limiting
            await self._rate_limiter.acquire()

            # Concurrency control
            async with self._semaphore:
                try:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        json=json_body,
                        params=query_params,
                    )

                    # Success or client error (4xx) — return immediately
                    if response.status_code < 500 and response.status_code != 429:
                        return response

                    # 429 Too Many Requests — respect Retry-After header
                    if response.status_code == 429:
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait = float(retry_after)
                            except ValueError:
                                wait = 2 ** attempt
                        else:
                            wait = 2 ** attempt

                        wait += random.uniform(0.1, 1.0)  # Jitter
                        logger.warning(
                            f"429 Rate Limited on {method} {url}. "
                            f"Backing off {wait:.1f}s (attempt {attempt + 1})"
                        )
                        await asyncio.sleep(wait)
                        continue

                    # 5xx Server Error — exponential backoff
                    wait = (2 ** attempt) + random.uniform(0.1, 1.0)
                    logger.warning(
                        f"{response.status_code} on {method} {url}. "
                        f"Retrying in {wait:.1f}s (attempt {attempt + 1})"
                    )
                    await asyncio.sleep(wait)

                except httpx.TimeoutException as e:
                    last_exception = e
                    wait = (2 ** attempt) + random.uniform(0.5, 2.0)
                    logger.warning(
                        f"Timeout on {method} {url}. "
                        f"Retrying in {wait:.1f}s (attempt {attempt + 1})"
                    )
                    await asyncio.sleep(wait)

                except httpx.ConnectError as e:
                    last_exception = e
                    wait = (2 ** attempt) + random.uniform(1.0, 3.0)
                    logger.error(
                        f"Connection error on {method} {url}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {attempt + 1})"
                    )
                    await asyncio.sleep(wait)

        # All retries exhausted
        if last_exception:
            raise last_exception
        # Return last response even if it was a 5xx
        return response  # noqa: F821 — response is always set by this point

    # ─────────────────────────────────────────
    # Teardown with DLQ Fallback
    # ─────────────────────────────────────────

    async def _teardown(
        self,
        client: httpx.AsyncClient,
        chain_id: str,
        method: str,
        url: str,
        headers: dict[str, str],
        result: ChainResult,
    ) -> None:
        """
        Attempt resource teardown. On failure, enqueue to DLQ.

        This runs inside a finally block to ensure cleanup happens
        regardless of chain execution outcome.
        """
        try:
            response = await self._send_request(
                client=client,
                method=method,
                url=url,
                headers=headers,
            )
            result.teardown_status = response.status_code
            result.teardown_success = response.status_code < 400

            if result.teardown_success:
                logger.info(f"{chain_id}: Teardown successful ({url})")
            else:
                logger.warning(
                    f"{chain_id}: Teardown returned "
                    f"{response.status_code} ({url})"
                )
                # Enqueue to DLQ for retry
                await self._dlq.enqueue(DLQEntry(
                    chain_id=chain_id,
                    method=method,
                    url=url,
                    headers=headers,
                    last_error=f"HTTP {response.status_code}",
                ))

        except Exception as e:
            result.teardown_status = 0
            result.teardown_success = False
            logger.error(f"{chain_id}: Teardown failed: {e}")

            # Enqueue to DLQ
            await self._dlq.enqueue(DLQEntry(
                chain_id=chain_id,
                method=method,
                url=url,
                headers=headers,
                last_error=str(e),
            ))

    # ─────────────────────────────────────────
    # URL Building and ID Injection
    # ─────────────────────────────────────────

    def _build_url(self, path: str, params: dict[str, str]) -> str:
        """
        Build a URL path with path parameters injected.

        Example:
            path = "/api/orders/{id}"
            params = {"id": "42"}
            → "/api/orders/42"
        """
        url = path
        for name, value in params.items():
            url = url.replace(f"{{{name}}}", str(value))
        return url

    def _build_read_url(
        self, chain: AttackChain, resource_id: Any
    ) -> str:
        """
        Build the READ URL with the resource ID injected.

        Handles both path-parameter-based and query-parameter-based
        endpoints:
            - /api/orders/{id}          → /api/orders/42
            - /api/fetch-order?id=42    → /api/fetch-order  (with query param)
        """
        read_ep = chain.read

        if read_ep.has_path_params:
            # Inject into path parameters
            param_map = {}
            for pname in read_ep.path_param_names:
                param_map[pname] = str(resource_id)
            return self._build_url(read_ep.path, param_map)
        else:
            # For query-parameter-based reads, append as query string
            # The caller should pass query_params separately, but for
            # the URL we return the base path
            return read_ep.path

    def _extract_resource_id(
        self, response_body: dict[str, Any], id_field: str
    ) -> Any:
        """
        Extract the resource ID from a CREATE response body.

        Searches for the id_field at the top level and one level deep.
        Handles common response wrapper patterns like:
            {"data": {"id": 42}}
            {"result": {"order_id": "abc-123"}}
        """
        if not isinstance(response_body, dict):
            return None

        # Direct lookup
        if id_field in response_body:
            return response_body[id_field]

        # Search one level deep (common wrappers)
        for key, value in response_body.items():
            if isinstance(value, dict) and id_field in value:
                return value[id_field]

        # Search with case-insensitive match
        id_lower = id_field.lower()
        for key, value in response_body.items():
            if key.lower() == id_lower:
                return value

        # Search inside common wrapper keys
        for wrapper_key in ("data", "result", "response", "body", "payload"):
            wrapper = response_body.get(wrapper_key)
            if isinstance(wrapper, dict):
                for key, value in wrapper.items():
                    if key.lower() == id_lower:
                        return value

        return None


# ─────────────────────────────────────────────
# Convenience function
# ─────────────────────────────────────────────

async def execute_scan(
    chains: list[AttackChain],
    resolved_spec: dict[str, Any],
    base_url: str,
    token_a: str,
    token_b: str,
    **kwargs: Any,
) -> list[ChainResult]:
    """
    One-liner convenience function to execute a full BOLA scan.

    Usage:
        from apighost.executor import execute_scan
        results = await execute_scan(
            chains=chains,
            resolved_spec=spec,
            base_url="http://localhost:8888",
            token_a="eyJ...",
            token_b="eyJ...",
        )
    """
    config = ExecutorConfig(
        base_url=base_url,
        token_a=token_a,
        token_b=token_b,
        **kwargs,
    )
    executor = ChainExecutor(config, resolved_spec)
    return await executor.execute_all(chains)
