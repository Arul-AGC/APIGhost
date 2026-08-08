"""
APIGhost Verdict Engine — Multi-Signal Weighted BOLA Detection

Determines whether a Broken Object Level Authorization (BOLA) vulnerability
exists by combining five independent signals into a single weighted score.

THE CORE INSIGHT — Why Status Codes Alone Are Not Enough:
    Many APIs return ``200 OK`` with a body like ``{"error": "Not authorized"}``
    or a generic landing page.  Relying solely on HTTP status codes produces
    false positives.  This engine *proves* that User B saw the same specific
    data that User A created by analyzing response *structure* and *values*.

Signals (weights sum to 1.0):
    1. Status Code Analysis       — weight 0.30
    2. Structural Similarity      — weight 0.35  (Jaccard Index on JSON key-paths)
    3. Value-Level Data Leakage   — weight 0.20  (leaf-value overlap)
    4. Error Keyword Penalty      — weight 0.10  (denial phrases in body text)
    5. Content-Length Ratio        — weight 0.05  (serialized size similarity)

Usage::

    from apighost.verdict import VerdictEngine
    engine = VerdictEngine()
    result = engine.evaluate(chain_result)
    print(result.verdict, result.score, result.signals)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from apighost.models import ChainResult, Verdict

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

SIGNAL_WEIGHTS: dict[str, float] = {
    "status_code":              0.30,
    "structural_similarity":    0.35,
    "data_leakage":             0.20,
    "error_keywords":           0.10,
    "content_length":           0.05,
}

# Values that are too common to be meaningful evidence of data leakage.
_TRIVIAL_VALUES: set[str] = {
    "true", "false", "null", "none", "",
    "0", "1", "0.0", "1.0",
}

# Denial keywords — if any of these appear in the attacker body (case-
# insensitive), the API is rejecting access regardless of status code.
_DENIAL_KEYWORDS: list[str] = [
    "forbidden",
    "unauthorized",
    "access denied",
    "permission denied",
    "not allowed",
    "not found",
    "invalid token",
]

_DENIAL_PATTERN: re.Pattern[str] = re.compile(
    "|".join(re.escape(kw) for kw in _DENIAL_KEYWORDS),
    re.IGNORECASE,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_key_paths(obj: Any, prefix: str = "") -> set[str]:
    """Recursively extract all JSON key-paths from a nested structure.

    Nested dicts produce dot-separated paths (``address.street``).
    Lists of dicts produce bracketed paths (``items[].name``).

    Args:
        obj: The JSON-deserialised object to walk.
        prefix: Internal accumulator for the current path prefix.

    Returns:
        A set of dot-path strings representing every key in the tree.

    Examples:
        >>> sorted(_extract_key_paths({"a": 1, "b": {"c": 2}}))
        ['a', 'b', 'b.c']
        >>> sorted(_extract_key_paths({"items": [{"id": 1}]}))
        ['items', 'items[].id']
    """
    paths: set[str] = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            current = f"{prefix}.{key}" if prefix else key
            paths.add(current)
            paths.update(_extract_key_paths(value, current))

    elif isinstance(obj, list):
        # Use the first element as representative of the list structure.
        list_prefix = f"{prefix}[]" if prefix else "[]"
        for item in obj[:1]:  # only first element to avoid duplication
            paths.update(_extract_key_paths(item, list_prefix))

    return paths


def _extract_leaf_values(obj: Any) -> set[str]:
    """Recursively extract all leaf (scalar) values from a nested structure.

    Values are normalised to their lowercase string representation so that
    comparisons are type- and case-insensitive.

    Args:
        obj: The JSON-deserialised object to walk.

    Returns:
        A set of stringified leaf values, excluding trivial ones.
    """
    values: set[str] = set()

    if isinstance(obj, dict):
        for value in obj.values():
            values.update(_extract_leaf_values(value))
    elif isinstance(obj, list):
        for item in obj:
            values.update(_extract_leaf_values(item))
    else:
        str_val = str(obj).strip().lower()
        if str_val not in _TRIVIAL_VALUES:
            values.add(str_val)

    return values


# ── Verdict Engine ───────────────────────────────────────────────────────────

class VerdictEngine:
    """Multi-signal weighted scoring engine for BOLA verdict determination.

    Each of the five signal methods is ``@staticmethod`` so it can be unit-
    tested in isolation without instantiating the engine.

    Typical usage::

        engine = VerdictEngine()
        result = engine.evaluate(chain_result)
        # result.verdict, result.score, result.signals are now populated.
    """

    # ── Signal 1: Status Code ────────────────────────────────────────────

    @staticmethod
    def _score_status_code(owner_status: int, attacker_status: int) -> float:
        """Score the HTTP status-code pair.

        This is the *weakest* signal by design — a 200 from the attacker is
        suspicious but far from proof.

        Scoring rules:
            - Attacker 200 **and** owner 200 → ``1.0`` (same access level)
            - Attacker 401 or 403            → ``0.0`` (properly denied)
            - Attacker 404                   → ``0.1`` (may be obfuscation)
            - Attacker 5xx                   → ``-1.0`` (sentinel for ERROR)
            - All other codes                → ``0.2`` (unknown / redirect / etc.)

        Args:
            owner_status:    HTTP status code from User A's read.
            attacker_status: HTTP status code from User B's read.

        Returns:
            A float between ``0.0`` and ``1.0``, or ``-1.0`` for server errors.
        """
        if 500 <= attacker_status < 600:
            logger.warning(
                "Server error (%d) during attacker request — marking ERROR",
                attacker_status,
            )
            return -1.0  # Sentinel: triggers Verdict.ERROR

        if attacker_status in (401, 403):
            logger.debug("Attacker properly denied (%d)", attacker_status)
            return 0.0

        if attacker_status == 404:
            logger.debug("Attacker got 404 — possible obfuscation")
            return 0.1

        if attacker_status == 200 and owner_status == 200:
            logger.debug("Both owner and attacker received 200")
            return 1.0

        # Catch-all for 3xx, other 2xx, 4xx we haven't special-cased, etc.
        logger.debug(
            "Uncommon status pair: owner=%d attacker=%d",
            owner_status, attacker_status,
        )
        return 0.2

    # ── Signal 2: Structural Similarity (Jaccard) ────────────────────────

    @staticmethod
    def _score_structural_similarity(
        owner_body: dict[str, Any],
        attacker_body: dict[str, Any],
    ) -> float:
        """Compute the Jaccard Index over recursive JSON key-paths.

        ``J(A, B) = |A ∩ B| / |A ∪ B|``

        If both responses share the *exact same structure* the score is 1.0,
        meaning the attacker is seeing the same kind of object as the owner.
        If the structures are completely disjoint (e.g. an error object vs. a
        resource object) the score is 0.0.

        Args:
            owner_body:    Parsed JSON body from User A's read.
            attacker_body: Parsed JSON body from User B's read.

        Returns:
            Jaccard similarity in ``[0.0, 1.0]``.
        """
        owner_keys = _extract_key_paths(owner_body)
        attacker_keys = _extract_key_paths(attacker_body)

        if not owner_keys and not attacker_keys:
            logger.debug("Both bodies empty — structural similarity = 0.0")
            return 0.0

        intersection = owner_keys & attacker_keys
        union = owner_keys | attacker_keys

        jaccard = len(intersection) / len(union) if union else 0.0

        logger.debug(
            "Jaccard structural similarity: %.3f "
            "(|intersection|=%d, |union|=%d, owner_keys=%s, attacker_keys=%s)",
            jaccard,
            len(intersection),
            len(union),
            sorted(owner_keys),
            sorted(attacker_keys),
        )
        return jaccard

    # ── Signal 3: Value-Level Data Leakage ───────────────────────────────

    @staticmethod
    def _score_data_leakage(
        owner_body: dict[str, Any],
        attacker_body: dict[str, Any],
    ) -> float:
        """Check how many of the *owner's* specific leaf values leaked into
        the attacker's response.

        A high ratio means the attacker is seeing the exact data that the
        owner created — strong evidence of BOLA.

        Trivial values (``true``, ``false``, ``null``, ``0``, ``1``, empty
        strings) are excluded so they don't inflate the score.

        Args:
            owner_body:    Parsed JSON body from User A's read.
            attacker_body: Parsed JSON body from User B's read.

        Returns:
            Ratio of leaked values in ``[0.0, 1.0]``.
        """
        owner_values = _extract_leaf_values(owner_body)
        if not owner_values:
            logger.debug("No non-trivial owner values — leakage score = 0.0")
            return 0.0

        attacker_values = _extract_leaf_values(attacker_body)
        leaked = owner_values & attacker_values

        ratio = len(leaked) / len(owner_values)

        logger.debug(
            "Data leakage ratio: %.3f (%d/%d leaked, leaked_values=%s)",
            ratio,
            len(leaked),
            len(owner_values),
            sorted(leaked),
        )
        return ratio

    # ── Signal 4: Error Keyword Penalty ──────────────────────────────────

    @staticmethod
    def _score_error_keywords(attacker_body: dict[str, Any]) -> float:
        """Scan the attacker's response for denial/error keywords.

        Many APIs return ``200 OK`` with a JSON body that contains phrases
        like ``"error": "Forbidden"`` or ``"message": "Access denied"``.
        This signal catches those false positives.

        Args:
            attacker_body: Parsed JSON body from User B's read.

        Returns:
            ``0.0`` if denial keywords are found (access is denied despite
            the status code), ``1.0`` otherwise.
        """
        try:
            serialized = json.dumps(attacker_body, default=str).lower()
        except (TypeError, ValueError):
            serialized = str(attacker_body).lower()

        match = _DENIAL_PATTERN.search(serialized)
        if match:
            logger.debug(
                "Denial keyword detected in attacker body: '%s'",
                match.group(),
            )
            return 0.0

        return 1.0

    # ── Signal 5: Content-Length Ratio ────────────────────────────────────

    @staticmethod
    def _score_content_length(
        owner_body: dict[str, Any],
        attacker_body: dict[str, Any],
    ) -> float:
        """Compare serialized JSON sizes of owner vs. attacker responses.

        If the attacker gets back a response of roughly the same size as the
        owner's, it's another hint they received real data rather than a tiny
        error message.

        Scoring:
            - ratio ≥ 0.8 → ``1.0``
            - Otherwise   → the ratio itself (linear fall-off)
            - Empty responses → ``0.0``

        Args:
            owner_body:    Parsed JSON body from User A's read.
            attacker_body: Parsed JSON body from User B's read.

        Returns:
            Similarity score in ``[0.0, 1.0]``.
        """
        try:
            owner_json = json.dumps(owner_body, sort_keys=True, default=str)
            attacker_json = json.dumps(attacker_body, sort_keys=True, default=str)
        except (TypeError, ValueError):
            owner_json = str(owner_body)
            attacker_json = str(attacker_body)

        owner_len = len(owner_json)
        attacker_len = len(attacker_json)

        if owner_len == 0 and attacker_len == 0:
            logger.debug("Both bodies empty — content-length score = 0.0")
            return 0.0

        if owner_len == 0 or attacker_len == 0:
            logger.debug("One body empty — content-length score = 0.0")
            return 0.0

        # Ratio is always ≤ 1.0 (smaller / larger).
        ratio = min(owner_len, attacker_len) / max(owner_len, attacker_len)

        score = 1.0 if ratio >= 0.8 else ratio

        logger.debug(
            "Content-length ratio: %.3f (owner=%d, attacker=%d) → score=%.3f",
            ratio, owner_len, attacker_len, score,
        )
        return score

    # ── Weighted Aggregation ─────────────────────────────────────────────

    @staticmethod
    def _compute_weighted_score(signals: dict[str, float]) -> float:
        """Aggregate individual signal scores using pre-defined weights.

        If any signal returned the ``-1.0`` sentinel (server error on
        status_code), the result is ``-1.0`` so the caller can map it to
        ``Verdict.ERROR``.

        Args:
            signals: Mapping of signal name → score (each in ``[0.0, 1.0]``
                     or ``-1.0`` for errors).

        Returns:
            Weighted sum in ``[0.0, 1.0]``, or ``-1.0`` for ERROR.
        """
        # Check for the error sentinel first.
        if signals.get("status_code", 0.0) == -1.0:
            return -1.0

        weighted_sum = 0.0
        for signal_name, weight in SIGNAL_WEIGHTS.items():
            score = signals.get(signal_name, 0.0)
            weighted_sum += weight * score
            logger.debug(
                "  %s: raw=%.3f × weight=%.2f = %.4f",
                signal_name, score, weight, weight * score,
            )

        # Clamp to [0.0, 1.0] in case of floating-point drift.
        weighted_sum = max(0.0, min(1.0, weighted_sum))

        logger.debug("Weighted aggregate score: %.4f", weighted_sum)
        return weighted_sum

    @staticmethod
    def _score_to_verdict(score: float) -> Verdict:
        """Map a numeric score to a :class:`Verdict` enum member.

        Thresholds:
            - ``score == -1.0``  → :attr:`Verdict.ERROR`
            - ``score >= 0.75``  → :attr:`Verdict.CONFIRMED`
            - ``score >= 0.50``  → :attr:`Verdict.LIKELY`
            - ``score >= 0.25``  → :attr:`Verdict.POSSIBLE`
            - ``score <  0.25``  → :attr:`Verdict.SECURE`

        Args:
            score: The weighted aggregate score.

        Returns:
            The appropriate :class:`Verdict` value.
        """
        if score == -1.0:
            return Verdict.ERROR
        if score >= 0.75:
            return Verdict.CONFIRMED
        if score >= 0.50:
            return Verdict.LIKELY
        if score >= 0.25:
            return Verdict.POSSIBLE
        return Verdict.SECURE

    # ── Public API ───────────────────────────────────────────────────────

    def evaluate(self, result: ChainResult) -> ChainResult:
        """Run all five signals against a single chain result and set the
        verdict, score, and signal breakdown.

        This method *mutates* the ``result`` in place and also returns it
        for convenience.

        Args:
            result: A :class:`ChainResult` populated by the Executor with
                    HTTP status codes and parsed response bodies.

        Returns:
            The same ``result`` with ``verdict``, ``score``, and ``signals``
            populated.
        """
        chain_id = result.chain.chain_id
        logger.info("Evaluating chain %s (%s)", chain_id, result.chain.resource_name)

        # If the chain already has an execution error, mark it ERROR and bail.
        if result.error:
            logger.warning("Chain %s has execution error: %s", chain_id, result.error)
            result.verdict = Verdict.ERROR
            result.score = 0.0
            result.signals = {}
            return result

        # Compute each signal independently.
        signals: dict[str, float] = {
            "status_code": self._score_status_code(
                result.read_as_owner_status,
                result.read_as_attacker_status,
            ),
            "structural_similarity": self._score_structural_similarity(
                result.read_as_owner_body,
                result.read_as_attacker_body,
            ),
            "data_leakage": self._score_data_leakage(
                result.read_as_owner_body,
                result.read_as_attacker_body,
            ),
            "error_keywords": self._score_error_keywords(
                result.read_as_attacker_body,
            ),
            "content_length": self._score_content_length(
                result.read_as_owner_body,
                result.read_as_attacker_body,
            ),
        }

        # Aggregate and determine verdict.
        score = self._compute_weighted_score(signals)
        verdict = self._score_to_verdict(score)

        # Populate result fields.
        result.signals = signals
        result.score = round(score, 4) if score != -1.0 else 0.0
        result.verdict = verdict

        logger.info(
            "Chain %s → %s (score=%.4f) signals=%s",
            chain_id,
            verdict.value,
            result.score,
            {k: round(v, 3) for k, v in signals.items()},
        )

        return result

    def evaluate_all(self, results: list[ChainResult]) -> list[ChainResult]:
        """Evaluate a batch of chain results.

        Args:
            results: List of :class:`ChainResult` objects from the Executor.

        Returns:
            The same list with all items evaluated in place.
        """
        logger.info("Evaluating %d chain result(s)", len(results))
        for result in results:
            self.evaluate(result)
        return results
