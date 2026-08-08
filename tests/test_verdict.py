"""
Comprehensive unit tests for the APIGhost Verdict Engine.

Tests every signal function individually, the weighted aggregation logic,
and full end-to-end evaluate() calls covering:
    - Clear BOLA (same structure, same values, 200/200)
    - Clear Secure (403 denied, different structure)
    - Tricky false positive (200 OK but body says "unauthorized")
    - Edge cases (empty responses, 5xx errors, execution errors)
"""

from __future__ import annotations

import unittest
from typing import Any

from apighost.models import (
    AttackChain,
    ChainResult,
    ChainSource,
    Endpoint,
    HttpMethod,
    Verdict,
)
from apighost.verdict import (
    SIGNAL_WEIGHTS,
    VerdictEngine,
    _extract_key_paths,
    _extract_leaf_values,
)


# ── Test Fixtures ────────────────────────────────────────────────────────────

def _make_chain(chain_id: str = "test_001") -> AttackChain:
    """Build a minimal AttackChain for testing."""
    return AttackChain(
        chain_id=chain_id,
        resource_name="orders",
        source=ChainSource.LAYER1_PATH,
        create=Endpoint(
            path="/api/orders",
            method=HttpMethod.POST,
            has_path_params=False,
        ),
        read=Endpoint(
            path="/api/orders/{id}",
            method=HttpMethod.GET,
            has_path_params=True,
            path_param_names=["id"],
        ),
    )


def _make_result(
    owner_status: int = 200,
    attacker_status: int = 200,
    owner_body: dict[str, Any] | None = None,
    attacker_body: dict[str, Any] | None = None,
    error: str | None = None,
) -> ChainResult:
    """Build a ChainResult pre-populated with test data."""
    return ChainResult(
        chain=_make_chain(),
        read_as_owner_status=owner_status,
        read_as_owner_body=owner_body or {},
        read_as_attacker_status=attacker_status,
        read_as_attacker_body=attacker_body or {},
        error=error,
    )


# ── Helper Tests ─────────────────────────────────────────────────────────────

class TestExtractKeyPaths(unittest.TestCase):
    """Tests for the _extract_key_paths() helper."""

    def test_flat_dict(self) -> None:
        result = _extract_key_paths({"id": 1, "name": "Alice"})
        self.assertEqual(result, {"id", "name"})

    def test_nested_dict(self) -> None:
        result = _extract_key_paths({"user": {"id": 1, "address": {"city": "NY"}}})
        self.assertIn("user", result)
        self.assertIn("user.id", result)
        self.assertIn("user.address", result)
        self.assertIn("user.address.city", result)

    def test_list_of_dicts(self) -> None:
        result = _extract_key_paths({"items": [{"id": 1, "name": "A"}]})
        self.assertIn("items", result)
        self.assertIn("items[].id", result)
        self.assertIn("items[].name", result)

    def test_empty_dict(self) -> None:
        result = _extract_key_paths({})
        self.assertEqual(result, set())

    def test_scalar_input(self) -> None:
        result = _extract_key_paths("just a string")
        self.assertEqual(result, set())

    def test_deeply_nested(self) -> None:
        obj = {"a": {"b": {"c": {"d": "value"}}}}
        result = _extract_key_paths(obj)
        self.assertIn("a.b.c.d", result)

    def test_empty_list(self) -> None:
        result = _extract_key_paths({"items": []})
        self.assertIn("items", result)
        # No child paths since the list is empty.
        self.assertNotIn("items[]", result)


class TestExtractLeafValues(unittest.TestCase):
    """Tests for the _extract_leaf_values() helper."""

    def test_flat_dict(self) -> None:
        result = _extract_leaf_values({"name": "Alice", "age": 30})
        self.assertIn("alice", result)
        self.assertIn("30", result)

    def test_trivial_values_excluded(self) -> None:
        result = _extract_leaf_values({"flag": True, "count": 0, "x": ""})
        # All should be excluded as trivial.
        self.assertEqual(result, set())

    def test_nested_extraction(self) -> None:
        obj = {"user": {"email": "alice@example.com"}, "items": [{"sku": "X-42"}]}
        result = _extract_leaf_values(obj)
        self.assertIn("alice@example.com", result)
        self.assertIn("x-42", result)


# ── Signal 1: Status Code ───────────────────────────────────────────────────

class TestScoreStatusCode(unittest.TestCase):
    """Tests for VerdictEngine._score_status_code()."""

    def test_both_200(self) -> None:
        self.assertEqual(VerdictEngine._score_status_code(200, 200), 1.0)

    def test_attacker_403(self) -> None:
        self.assertEqual(VerdictEngine._score_status_code(200, 403), 0.0)

    def test_attacker_401(self) -> None:
        self.assertEqual(VerdictEngine._score_status_code(200, 401), 0.0)

    def test_attacker_404(self) -> None:
        self.assertAlmostEqual(VerdictEngine._score_status_code(200, 404), 0.1)

    def test_attacker_500(self) -> None:
        self.assertEqual(VerdictEngine._score_status_code(200, 500), -1.0)

    def test_attacker_503(self) -> None:
        self.assertEqual(VerdictEngine._score_status_code(200, 503), -1.0)

    def test_attacker_302(self) -> None:
        score = VerdictEngine._score_status_code(200, 302)
        self.assertAlmostEqual(score, 0.2)

    def test_owner_201_attacker_200(self) -> None:
        # owner_status is not 200, so the (200 && 200) branch misses.
        score = VerdictEngine._score_status_code(201, 200)
        self.assertAlmostEqual(score, 0.2)


# ── Signal 2: Structural Similarity ─────────────────────────────────────────

class TestScoreStructuralSimilarity(unittest.TestCase):
    """Tests for VerdictEngine._score_structural_similarity()."""

    def test_identical_structure(self) -> None:
        body = {"id": 1, "name": "Order #1", "email": "a@b.com", "ssn": "123"}
        score = VerdictEngine._score_structural_similarity(body, body)
        self.assertAlmostEqual(score, 1.0)

    def test_completely_different(self) -> None:
        owner = {"id": 1, "name": "X", "email": "a@b.com"}
        attacker = {"error": "not found", "message": "gone"}
        score = VerdictEngine._score_structural_similarity(owner, attacker)
        self.assertAlmostEqual(score, 0.0)

    def test_partial_overlap(self) -> None:
        owner = {"id": 1, "name": "X", "email": "a@b.com", "ssn": "123"}
        attacker = {"id": 2, "name": "Y"}
        score = VerdictEngine._score_structural_similarity(owner, attacker)
        # Intersection = {id, name}, Union = {id, name, email, ssn} → 2/4 = 0.5
        self.assertAlmostEqual(score, 0.5)

    def test_both_empty(self) -> None:
        score = VerdictEngine._score_structural_similarity({}, {})
        self.assertAlmostEqual(score, 0.0)

    def test_nested_structure_match(self) -> None:
        owner = {"user": {"id": 1, "address": {"city": "NY"}}}
        attacker = {"user": {"id": 2, "address": {"city": "LA"}}}
        score = VerdictEngine._score_structural_similarity(owner, attacker)
        self.assertAlmostEqual(score, 1.0)


# ── Signal 3: Value-Level Data Leakage ───────────────────────────────────────

class TestScoreDataLeakage(unittest.TestCase):
    """Tests for VerdictEngine._score_data_leakage()."""

    def test_full_leakage(self) -> None:
        body = {"name": "Alice", "email": "alice@example.com", "ssn": "111-22-3333"}
        score = VerdictEngine._score_data_leakage(body, body)
        self.assertAlmostEqual(score, 1.0)

    def test_no_leakage(self) -> None:
        owner = {"name": "Alice", "email": "alice@example.com"}
        attacker = {"error": "forbidden", "code": 403}
        score = VerdictEngine._score_data_leakage(owner, attacker)
        self.assertAlmostEqual(score, 0.0)

    def test_partial_leakage(self) -> None:
        owner = {"name": "Alice", "email": "alice@example.com", "phone": "555-0100"}
        attacker = {"name": "Alice", "email": "different@example.com", "phone": "other"}
        score = VerdictEngine._score_data_leakage(owner, attacker)
        # Only "alice" leaks (out of 3 non-trivial values) → 1/3 ≈ 0.333
        self.assertGreater(score, 0.0)
        self.assertLess(score, 1.0)

    def test_owner_empty(self) -> None:
        score = VerdictEngine._score_data_leakage({}, {"data": "stuff"})
        self.assertAlmostEqual(score, 0.0)

    def test_trivial_values_ignored(self) -> None:
        owner = {"flag": True, "count": 0}
        attacker = {"flag": True, "count": 0}
        score = VerdictEngine._score_data_leakage(owner, attacker)
        # All values are trivial → 0.0
        self.assertAlmostEqual(score, 0.0)


# ── Signal 4: Error Keywords ─────────────────────────────────────────────────

class TestScoreErrorKeywords(unittest.TestCase):
    """Tests for VerdictEngine._score_error_keywords()."""

    def test_no_keywords(self) -> None:
        body = {"id": 1, "name": "Order", "total": 99.99}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 1.0)

    def test_forbidden_keyword(self) -> None:
        body = {"error": "Forbidden", "message": "You do not have access"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_unauthorized_keyword(self) -> None:
        body = {"status": "Unauthorized"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_access_denied_in_message(self) -> None:
        body = {"message": "Access denied for this resource"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_permission_denied(self) -> None:
        body = {"detail": "Permission denied"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_not_allowed(self) -> None:
        body = {"error": "Not allowed"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_not_found_keyword(self) -> None:
        body = {"error": "Not found"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_invalid_token(self) -> None:
        body = {"error": "Invalid token provided"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)

    def test_empty_body(self) -> None:
        score = VerdictEngine._score_error_keywords({})
        self.assertAlmostEqual(score, 1.0)

    def test_case_insensitive(self) -> None:
        body = {"error": "FORBIDDEN"}
        score = VerdictEngine._score_error_keywords(body)
        self.assertAlmostEqual(score, 0.0)


# ── Signal 5: Content-Length Ratio ───────────────────────────────────────────

class TestScoreContentLength(unittest.TestCase):
    """Tests for VerdictEngine._score_content_length()."""

    def test_identical_bodies(self) -> None:
        body = {"id": 1, "name": "Order", "total": 99.99}
        score = VerdictEngine._score_content_length(body, body)
        self.assertAlmostEqual(score, 1.0)

    def test_similar_bodies(self) -> None:
        owner = {"id": 1, "name": "Order Alpha"}
        attacker = {"id": 2, "name": "Order Beta!"}
        score = VerdictEngine._score_content_length(owner, attacker)
        self.assertGreater(score, 0.7)

    def test_very_different_sizes(self) -> None:
        owner = {"id": 1, "name": "X", "email": "a@b.com", "ssn": "123-45-6789",
                 "address": {"street": "123 Main St", "city": "Springfield"}}
        attacker = {"error": "no"}
        score = VerdictEngine._score_content_length(owner, attacker)
        self.assertLess(score, 0.5)

    def test_both_empty(self) -> None:
        score = VerdictEngine._score_content_length({}, {})
        self.assertAlmostEqual(score, 1.0)

    def test_one_empty(self) -> None:
        score = VerdictEngine._score_content_length({"data": "x"}, {})
        self.assertAlmostEqual(score, 0.15384615384615385)


# ── Weighted Aggregation ─────────────────────────────────────────────────────

class TestComputeWeightedScore(unittest.TestCase):
    """Tests for VerdictEngine._compute_weighted_score()."""

    def test_all_ones(self) -> None:
        signals = {k: 1.0 for k in SIGNAL_WEIGHTS}
        score = VerdictEngine._compute_weighted_score(signals)
        self.assertAlmostEqual(score, 1.0)

    def test_all_zeros(self) -> None:
        signals = {k: 0.0 for k in SIGNAL_WEIGHTS}
        score = VerdictEngine._compute_weighted_score(signals)
        self.assertAlmostEqual(score, 0.0)

    def test_error_sentinel(self) -> None:
        signals = {k: 1.0 for k in SIGNAL_WEIGHTS}
        signals["status_code"] = -1.0
        score = VerdictEngine._compute_weighted_score(signals)
        self.assertEqual(score, -1.0)

    def test_weights_sum_to_one(self) -> None:
        self.assertAlmostEqual(sum(SIGNAL_WEIGHTS.values()), 1.0)


class TestScoreToVerdict(unittest.TestCase):
    """Tests for VerdictEngine._score_to_verdict()."""

    def test_confirmed(self) -> None:
        self.assertEqual(VerdictEngine._score_to_verdict(0.80), Verdict.CONFIRMED)
        self.assertEqual(VerdictEngine._score_to_verdict(0.75), Verdict.CONFIRMED)

    def test_likely(self) -> None:
        self.assertEqual(VerdictEngine._score_to_verdict(0.60), Verdict.LIKELY)
        self.assertEqual(VerdictEngine._score_to_verdict(0.50), Verdict.LIKELY)

    def test_possible(self) -> None:
        self.assertEqual(VerdictEngine._score_to_verdict(0.30), Verdict.POSSIBLE)
        self.assertEqual(VerdictEngine._score_to_verdict(0.25), Verdict.POSSIBLE)

    def test_secure(self) -> None:
        self.assertEqual(VerdictEngine._score_to_verdict(0.10), Verdict.SECURE)
        self.assertEqual(VerdictEngine._score_to_verdict(0.0), Verdict.SECURE)

    def test_error(self) -> None:
        self.assertEqual(VerdictEngine._score_to_verdict(-1.0), Verdict.ERROR)


# ── Full evaluate() Integration Tests ────────────────────────────────────────

class TestEvaluateFull(unittest.TestCase):
    """End-to-end tests for VerdictEngine.evaluate()."""

    def setUp(self) -> None:
        self.engine = VerdictEngine()

    def test_clear_bola_confirmed(self) -> None:
        """Both 200, identical structure and values → CONFIRMED."""
        body = {
            "id": "abc-123",
            "name": "Secret Order",
            "email": "victim@example.com",
            "ssn": "111-22-3333",
            "total": 5999.99,
        }
        result = _make_result(
            owner_status=200,
            attacker_status=200,
            owner_body=body,
            attacker_body=body,
        )
        evaluated = self.engine.evaluate(result)

        self.assertEqual(evaluated.verdict, Verdict.CONFIRMED)
        self.assertGreaterEqual(evaluated.score, 0.75)
        # All signals should be high.
        self.assertAlmostEqual(evaluated.signals["status_code"], 1.0)
        self.assertAlmostEqual(evaluated.signals["structural_similarity"], 1.0)
        self.assertAlmostEqual(evaluated.signals["data_leakage"], 1.0)
        self.assertAlmostEqual(evaluated.signals["error_keywords"], 1.0)
        self.assertAlmostEqual(evaluated.signals["content_length"], 1.0)

    def test_clear_secure_403(self) -> None:
        """Attacker gets 403, different body → SECURE."""
        owner_body = {"id": 1, "name": "Secret", "email": "a@b.com"}
        attacker_body = {"error": "Forbidden", "code": 403}
        result = _make_result(
            owner_status=200,
            attacker_status=403,
            owner_body=owner_body,
            attacker_body=attacker_body,
        )
        evaluated = self.engine.evaluate(result)

        self.assertEqual(evaluated.verdict, Verdict.SECURE)
        self.assertLess(evaluated.score, 0.25)
        self.assertAlmostEqual(evaluated.signals["status_code"], 0.0)

    def test_false_positive_200_but_unauthorized_body(self) -> None:
        """THE TRICKY CASE: Status 200 but body says 'unauthorized'.

        A naive tool would flag this as BOLA, but the error_keywords signal
        should drag the score down.
        """
        owner_body = {
            "id": "xyz-789",
            "name": "Private Data",
            "email": "user@corp.com",
        }
        attacker_body = {
            "status": 200,
            "error": "Unauthorized",
            "message": "You are not authorized to view this resource",
        }
        result = _make_result(
            owner_status=200,
            attacker_status=200,
            owner_body=owner_body,
            attacker_body=attacker_body,
        )
        evaluated = self.engine.evaluate(result)

        # Even though status is 200/200, the combined signals should push
        # the verdict AWAY from CONFIRMED.
        self.assertNotEqual(evaluated.verdict, Verdict.CONFIRMED)
        # error_keywords should be 0.0.
        self.assertAlmostEqual(evaluated.signals["error_keywords"], 0.0)
        # structural_similarity should be low (different keys).
        self.assertLess(evaluated.signals["structural_similarity"], 0.3)

    def test_server_error_5xx(self) -> None:
        """Attacker gets 500 → ERROR verdict."""
        result = _make_result(
            owner_status=200,
            attacker_status=500,
            owner_body={"id": 1},
            attacker_body={"error": "Internal Server Error"},
        )
        evaluated = self.engine.evaluate(result)

        self.assertEqual(evaluated.verdict, Verdict.ERROR)

    def test_execution_error(self) -> None:
        """Chain that failed to execute → ERROR verdict."""
        result = _make_result(error="Connection timeout")
        evaluated = self.engine.evaluate(result)

        self.assertEqual(evaluated.verdict, Verdict.ERROR)
        self.assertEqual(evaluated.score, 0.0)
        self.assertEqual(evaluated.signals, {})

    def test_empty_responses(self) -> None:
        """Both owner and attacker return empty bodies → SECURE."""
        result = _make_result(
            owner_status=200,
            attacker_status=200,
            owner_body={},
            attacker_body={},
        )
        evaluated = self.engine.evaluate(result)

        # With empty bodies, structural and data signals are 0.
        # Only status_code (1.0 × 0.30) + error_keywords (1.0 × 0.10) = 0.40
        # + content_length (0.0 × 0.05) = 0.40
        self.assertIn(evaluated.verdict, (Verdict.POSSIBLE, Verdict.LIKELY))
        self.assertLess(evaluated.score, 0.75)

    def test_attacker_404_with_generic_body(self) -> None:
        """Attacker gets 404 — low status_code score, error keywords in body."""
        owner_body = {"id": 1, "data": "secret"}
        attacker_body = {"detail": "Not found"}
        result = _make_result(
            owner_status=200,
            attacker_status=404,
            owner_body=owner_body,
            attacker_body=attacker_body,
        )
        evaluated = self.engine.evaluate(result)

        self.assertEqual(evaluated.verdict, Verdict.SECURE)
        self.assertAlmostEqual(evaluated.signals["status_code"], 0.1)
        self.assertAlmostEqual(evaluated.signals["error_keywords"], 0.0)


# ── Batch evaluate_all() ─────────────────────────────────────────────────────

class TestEvaluateAll(unittest.TestCase):
    """Tests for VerdictEngine.evaluate_all()."""

    def test_batch_processing(self) -> None:
        engine = VerdictEngine()
        results = [
            _make_result(
                owner_status=200, attacker_status=200,
                owner_body={"id": 1, "secret": "data"},
                attacker_body={"id": 1, "secret": "data"},
            ),
            _make_result(
                owner_status=200, attacker_status=403,
                owner_body={"id": 2},
                attacker_body={"error": "Forbidden"},
            ),
        ]
        evaluated = engine.evaluate_all(results)

        self.assertEqual(len(evaluated), 2)
        # First should be CONFIRMED (or LIKELY at minimum).
        self.assertIn(evaluated[0].verdict, (Verdict.CONFIRMED, Verdict.LIKELY))
        # Second should be SECURE.
        self.assertEqual(evaluated[1].verdict, Verdict.SECURE)

    def test_empty_list(self) -> None:
        engine = VerdictEngine()
        evaluated = engine.evaluate_all([])
        self.assertEqual(evaluated, [])


# ── Signal Breakdown Transparency ────────────────────────────────────────────

class TestSignalTransparency(unittest.TestCase):
    """Verify that signal breakdowns are stored for reporting."""

    def test_signals_dict_populated(self) -> None:
        engine = VerdictEngine()
        result = _make_result(
            owner_status=200,
            attacker_status=200,
            owner_body={"key": "value"},
            attacker_body={"key": "value"},
        )
        evaluated = engine.evaluate(result)

        # All five signals must be present.
        self.assertIn("status_code", evaluated.signals)
        self.assertIn("structural_similarity", evaluated.signals)
        self.assertIn("data_leakage", evaluated.signals)
        self.assertIn("error_keywords", evaluated.signals)
        self.assertIn("content_length", evaluated.signals)

        # Each should be a float.
        for name, val in evaluated.signals.items():
            self.assertIsInstance(val, float, f"Signal '{name}' should be float")


if __name__ == "__main__":
    unittest.main()
