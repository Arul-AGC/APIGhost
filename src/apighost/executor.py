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
from typing import Any, Callable

import httpx

from apighost.models import (
    AttackChain,
    ChainResult,
    Endpoint,
    HttpMethod,
    Verdict,
    AuthMode,
    ChainVariant,
)
from apighost.generator import DataGenerator, DependencyPrefetcher

logger = logging.getLogger(__name__)


def _mask_token(token: str) -> str:
    """Mask a token for safe logging, showing only the last 4 characters."""
    if len(token) <= 8:
        return "****" + token[-4:] if len(token) >= 4 else "****"
    return token[:4] + "****" + token[-4:]


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
    auth_mode: AuthMode = AuthMode.BEARER  # Authentication mode
    auth_header: str = "Authorization"     # Header name (for API_KEY and CUSTOM modes)
    auth_scheme: str = "Bearer"            # Scheme prefix (for BEARER mode)
    token_refresh_cmd: str | None = None   # Shell command to refresh expired tokens
    verify_ssl: bool = True                # Verify SSL certs


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
        # Data generator with Tier 3 dependency prefetching.
        # The prefetcher starts client-less (prefetch disabled); its client
        # is bound inside execute_all() once the httpx session exists.
        self.prefetcher = DependencyPrefetcher(resolved_spec)
        self.generator = DataGenerator(
            resolved_spec, prefetcher=self.prefetcher
        )

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
        """Build authorization headers for a given token based on auth mode."""
        logger.debug(f"Auth: {self.config.auth_mode.value} {_mask_token(token)}")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        match self.config.auth_mode:
            case AuthMode.BEARER:
                headers["Authorization"] = f"{self.config.auth_scheme} {token}"
            case AuthMode.API_KEY:
                headers[self.config.auth_header] = token
            case AuthMode.COOKIE:
                headers["Cookie"] = f"{self.config.auth_header}={token}"
            case AuthMode.BASIC:
                import base64
                encoded = base64.b64encode(token.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            case AuthMode.CUSTOM:
                headers[self.config.auth_header] = token
        
        return headers

    import subprocess
    def _refresh_token(self, token_type: str) -> str | None:
        """Run the token refresh command and return the new token.
        
        The refresh command should print the new token to stdout.
        We append the token_type ('a' or 'b') as an argument.
        """
        if not self.config.token_refresh_cmd:
            return None
        
        try:
            import subprocess
            cmd = f"{self.config.token_refresh_cmd} {token_type}"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                new_token = result.stdout.strip()
                logger.info(f"Token refreshed for user {token_type}: {_mask_token(new_token)}")
                return new_token
            else:
                logger.warning(f"Token refresh failed: {result.stderr.strip()}")
                return None
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return None

    async def execute_all(
        self,
        chains: list[AttackChain],
        progress_callback: Callable[[], None] | None = None,
    ) -> list[ChainResult]:
        """
        Execute all attack chains against the target API.

        Chains are executed sequentially (not concurrently) to maintain
        state integrity — each chain's CREATE must complete before
        its READ can run.

        Args:
            chains: List of AttackChain objects from the Chain Builder.
            progress_callback: Optional zero-arg callable invoked after each
                chain completes (e.g. to advance a progress bar).

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
            verify=self.config.verify_ssl,
        ) as client:
            # Enable Tier 3 dependency prefetching for this scan
            self.prefetcher.client = client
            self.prefetcher.auth_token = self.config.token_a

            for i, chain in enumerate(chains, 1):
                logger.info(
                    f"Executing chain {i}/{len(chains)}: "
                    f"{chain.chain_id} ({chain.resource_name})"
                )
                result = await self._execute_single_chain(client, chain)
                self.results.append(result)

                if progress_callback is not None:
                    progress_callback()

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
            # Async generation enables Tier 3 dependency prefetching
            # (harvesting real FK IDs from the target API before POSTing).
            if chain.variant == ChainVariant.BFLA:
                # BFLA doesn't need to CREATE with token_a, we just test the attack endpoint
                attack_ep = chain.attack
                attack_method = attack_ep.method.value
                payload = await self.generator.generate_payload_async(attack_ep)
                url = self._build_url(attack_ep.path, payload.get("path_params", {}))
                
                attacker_response = await self._send_request(
                    client=client,
                    method=attack_method,
                    url=url,
                    headers=self._auth_headers(self.config.token_b),
                    json_body=payload.get("body"),
                    query_params=payload.get("query_params"),
                )
                
                result.read_as_attacker_status = attacker_response.status_code
                try:
                    result.read_as_attacker_body = attacker_response.json()
                except (json.JSONDecodeError, ValueError):
                    result.read_as_attacker_body = {}
                
                logger.info(f"{chain.chain_id}: BFLA Attacker={result.read_as_attacker_status}")
                return result

            if chain.variant in (ChainVariant.RATE_LIMIT, ChainVariant.INJECTION):
                if not getattr(self.config, 'aggressive', False):
                    result.verdict = Verdict.SECURE
                    result.error = "Aggressive tests disabled. Use --aggressive."
                    return result
                
                if chain.variant == ChainVariant.RATE_LIMIT:
                    attack_ep = chain.attack
                    payload = await self.generator.generate_payload_async(attack_ep)
                    url = self._build_url(attack_ep.path, payload.get("path_params", {}))
                    
                    tasks = []
                    for _ in range(20):
                        tasks.append(client.request(
                            method=attack_ep.method.value,
                            url=url,
                            headers=self._auth_headers(self.config.token_b),
                            json=payload.get("body"),
                            params=payload.get("query_params")
                        ))
                    
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    statuses = [r.status_code for r in responses if not isinstance(r, Exception)]
                    
                    if 429 in statuses:
                        result.read_as_attacker_status = 429
                    else:
                        result.read_as_attacker_status = 200
                    
                    result.read_as_attacker_body = {"statuses": statuses}
                    return result

                if chain.variant == ChainVariant.INJECTION:
                    attack_ep = chain.attack
                    payload = await self.generator.generate_payload_async(attack_ep)
                    url = self._build_url(attack_ep.path, payload.get("path_params", {}))
                    
                    body = payload.get("body")
                    if isinstance(body, dict):
                        for k, v in body.items():
                            if isinstance(v, str):
                                body[k] = v + "' OR 1=1-- {{7*7}}"
                    
                    attacker_response = await self._send_request(
                        client=client,
                        method=attack_ep.method.value,
                        url=url,
                        headers=self._auth_headers(self.config.token_b),
                        json_body=body,
                        query_params=payload.get("query_params")
                    )
                    
                    result.read_as_attacker_status = attacker_response.status_code
                    try:
                        result.read_as_attacker_body = attacker_response.json()
                    except (json.JSONDecodeError, ValueError):
                        result.read_as_attacker_body = {"text": attacker_response.text}
                    
                    return result

            create_payload = await self.generator.generate_payload_async(
                chain.create
            )
            
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

            # Extract resource IDs from CREATE response
            resource_ids = self._extract_resource_ids(
                result.create_body, chain.id_fields
            )

            if not resource_ids:
                result.error = (
                    f"CREATE returned {result.create_status} but could not "
                    f"extract any of {chain.id_fields} from response body. "
                    f"Body: {json.dumps(result.create_body)[:200]}"
                )
                result.verdict = Verdict.ERROR
                logger.warning(f"{chain.chain_id}: {result.error}")
                return result

            result.resource_ids = resource_ids
            logger.info(
                f"{chain.chain_id}: Created resource with "
                f"IDs={resource_ids}"
            )

            # Push teardown onto LIFO stack
            if chain.delete:
                teardown_url = self._build_url(
                    chain.delete.path, resource_ids
                )
                if chain.delete.path_param_names:
                    # Prefer using the actual param names if they differ
                    param_map = {}
                    for pname in chain.delete.path_param_names:
                        # Try to find a matching ID by name, or just use the first available one (naive fallback)
                        val = resource_ids.get(pname)
                        if not val and resource_ids:
                            val = list(resource_ids.values())[0]
                        param_map[pname] = str(val)
                    teardown_url = self._build_url(chain.delete.path, param_map)

            # ── Phase 2: READ as Owner (User A) ──────────────
            read_url, read_query_params = self._build_read_url(
                chain, resource_ids
            )

            owner_response = await self._send_request(
                client=client,
                method=chain.read.method.value,
                url=read_url,
                headers=self._auth_headers(self.config.token_a),
                query_params=read_query_params,
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

            # ── Phase 3: ATTACK as Attacker (User B) ─────────
            attack_ep = chain.attack if chain.attack else chain.read
            attack_method = attack_ep.method.value
            
            if chain.variant == ChainVariant.READ:
                # Standard READ BOLA test
                attacker_response = await self._send_request(
                    client=client,
                    method=attack_method,
                    url=read_url,
                    headers=self._auth_headers(self.config.token_b),
                    query_params=read_query_params,
                )
            elif chain.variant == ChainVariant.UPDATE:
                # UPDATE BOLA test — attacker tries to modify owner's resource
                update_payload = await self.generator.generate_payload_async(attack_ep)
                attack_url = self._build_url(attack_ep.path, resource_ids)
                # Populate all path params
                if attack_ep.path_param_names:
                    param_map = {}
                    for pname in attack_ep.path_param_names:
                        val = resource_ids.get(pname)
                        if not val and resource_ids:
                            val = list(resource_ids.values())[0]
                        param_map[pname] = str(val)
                    attack_url = self._build_url(attack_ep.path, param_map)
                attacker_response = await self._send_request(
                    client=client,
                    method=attack_method,
                    url=attack_url,
                    headers=self._auth_headers(self.config.token_b),
                    json_body=update_payload.get("body"),
                )
            elif chain.variant == ChainVariant.DELETE:
                # DELETE BOLA test — attacker tries to delete owner's resource
                attack_url = self._build_url(attack_ep.path, resource_ids)
                if attack_ep.path_param_names:
                    param_map = {}
                    for pname in attack_ep.path_param_names:
                        val = resource_ids.get(pname)
                        if not val and resource_ids:
                            val = list(resource_ids.values())[0]
                        param_map[pname] = str(val)
                    attack_url = self._build_url(attack_ep.path, param_map)
                attacker_response = await self._send_request(
                    client=client,
                    method=attack_method,
                    url=attack_url,
                    headers=self._auth_headers(self.config.token_b),
                )
            elif chain.variant == ChainVariant.MASS_ASSIGNMENT:
                update_payload = await self.generator.generate_payload_async(attack_ep)
                canary_fields = {"is_admin": True, "role": "admin", "balance": 99999}
                if "body" in update_payload and isinstance(update_payload["body"], dict):
                    update_payload["body"].update(canary_fields)
                
                attack_url = self._build_url(attack_ep.path, resource_ids)
                if attack_ep.path_param_names:
                    param_map = {}
                    for pname in attack_ep.path_param_names:
                        val = resource_ids.get(pname)
                        if not val and resource_ids:
                            val = list(resource_ids.values())[0]
                        param_map[pname] = str(val)
                    attack_url = self._build_url(attack_ep.path, param_map)
                
                # Perform the attack with token_b
                attacker_response = await self._send_request(
                    client=client,
                    method=attack_method,
                    url=attack_url,
                    headers=self._auth_headers(self.config.token_b),
                    json_body=update_payload.get("body"),
                )
                
                # Read back with token_b (or token_a) to verify payload
                verify_response = await self._send_request(
                    client=client,
                    method=chain.read.method.value,
                    url=read_url,
                    headers=self._auth_headers(self.config.token_b),
                    query_params=read_query_params,
                )
                
                # We overwrite attacker_response with the read for verdict check
                attacker_response = verify_response
            elif chain.variant == ChainVariant.EXCESSIVE_DATA:
                attacker_response = await self._send_request(
                    client=client,
                    method=chain.read.method.value,
                    url=read_url,
                    headers=self._auth_headers(self.config.token_a),
                    query_params=read_query_params,
                )
            else:
                # Fallback to standard READ
                attacker_response = await self._send_request(
                    client=client,
                    method=chain.read.method.value,
                    url=read_url,
                    headers=self._auth_headers(self.config.token_b),
                    query_params=read_query_params,
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
                        # Auto-refresh on 401 if refresh command is configured
                        if response.status_code == 401 and self.config.token_refresh_cmd and attempt < self.config.max_retries:
                            # Determine which token to refresh based on the header
                            current_token_a_header = self._auth_headers(self.config.token_a)
                            if headers.get("Authorization") == current_token_a_header.get("Authorization") or \
                               headers.get("Cookie") == current_token_a_header.get("Cookie") or \
                               headers.get(self.config.auth_header) == current_token_a_header.get(self.config.auth_header):
                                token_type = "a"
                            else:
                                token_type = "b"
                            
                            new_token = self._refresh_token(token_type)
                            if new_token:
                                if token_type == "a":
                                    self.config.token_a = new_token
                                else:
                                    self.config.token_b = new_token
                                # Rebuild headers with new token and retry
                                headers = self._auth_headers(new_token)
                                continue
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
        self, chain: AttackChain, resource_ids: dict[str, Any]
    ) -> tuple[str, dict[str, str]]:
        """
        Build the READ URL and query params with the resource ID injected.

        Handles both path-parameter-based and query-parameter-based
        endpoints:
            - /api/orders/{id}          → ("/api/orders/42", {})
            - /api/fetch-order?id=42    → ("/api/fetch-order", {"id": "42"})

        Returns:
            Tuple of (URL path, query parameters dict). The caller passes
            the query params to httpx so Layer 2 (query-param) chains
            actually transmit the resource ID.
        """
        read_ep = chain.read

        if read_ep.has_path_params:
            param_map = {}
            for pname in read_ep.path_param_names:
                val = resource_ids.get(pname)
                if not val and resource_ids:
                    val = list(resource_ids.values())[0]
                param_map[pname] = str(val)
            return self._build_url(read_ep.path, param_map), {}

        # Query-parameter-based read
        query_params: dict[str, str] = {}
        for param in read_ep.parameters:
            if isinstance(param, dict) and param.get("in") == "query":
                pname = param.get("name")
                if pname in chain.id_fields:
                    query_params[pname] = str(resource_ids.get(pname, ""))

        return read_ep.path, query_params

    def _extract_resource_ids(
        self, response_body: dict[str, Any], id_fields: list[str]
    ) -> dict[str, Any]:
        """
        Extract multiple resource IDs from a CREATE response body.

        Searches for each id_field at the top level and one level deep.
        Returns a mapping of field_name -> value.
        """
        if not isinstance(response_body, dict):
            return {}

        extracted: dict[str, Any] = {}
        
        for id_field in id_fields:
            val = None
            id_lower = id_field.lower()
            
            # Direct lookup
            if id_field in response_body:
                val = response_body[id_field]
            
            # Search one level deep
            if val is None:
                for key, value in response_body.items():
                    if isinstance(value, dict) and id_field in value:
                        val = value[id_field]
                        break

            # Search with case-insensitive match
            if val is None:
                for key, value in response_body.items():
                    if key.lower() == id_lower:
                        val = value
                        break

            # Search inside common wrapper keys
            if val is None:
                for wrapper_key in ("data", "result", "response", "body", "payload"):
                    wrapper = response_body.get(wrapper_key)
                    if isinstance(wrapper, dict):
                        for key, value in wrapper.items():
                            if key.lower() == id_lower:
                                val = value
                                break
                    if val is not None:
                        break
            
            if val is not None:
                extracted[id_field] = val

        return extracted


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
