"""
Unit tests for the Data Generator engine.
"""

import json
import pytest
from pathlib import Path
from apighost.generator import DataGenerator
from apighost.models import Endpoint, HttpMethod, CrudRole

@pytest.fixture
def test_spec():
    spec_path = Path(__file__).parent / "test_spec.json"
    with open(spec_path) as f:
        return json.load(f)

def test_tier1_examples(test_spec):
    gen = DataGenerator(test_spec)
    # create dummy endpoint that has an example in requestBody
    schema = {
        "type": "object",
        "properties": {
            "email": {"type": "string", "example": "test@example.com"},
            "age": {"type": "integer", "default": 25}
        }
    }
    ep = Endpoint(
        method=HttpMethod.POST,
        path="/test",
        request_body_schema=schema
    )
    
    payload = gen.generate_payload(ep)
    body = payload["body"]
    
    assert body["email"] == "test@example.com"
    assert body["age"] == 25

def test_tier2_heuristics(test_spec):
    gen = DataGenerator(test_spec)
    schema = {
        "type": "object",
        "properties": {
            "user_email": {"type": "string", "format": "email"},
            "price": {"type": "number"},
            "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
            "id": {"type": "string", "format": "uuid"}
        }
    }
    ep = Endpoint(
        method=HttpMethod.POST,
        path="/test",
        request_body_schema=schema
    )
    
    payload = gen.generate_payload(ep)
    body = payload["body"]
    
    assert "@" in body["user_email"]
    assert isinstance(body["price"], float)
    assert 1 <= body["quantity"] <= 5
    assert len(body["id"]) == 36 # UUID length
