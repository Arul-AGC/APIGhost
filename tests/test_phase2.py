import pytest
import json
from httpx import Response
from apighost.chain_builder import ChainBuilder
from apighost.models import Endpoint, HttpMethod, ChainVariant, Verdict, ChainResult, AttackChain, ChainSource
from apighost.verdict import VerdictEngine
from apighost.executor import ChainExecutor, ExecutorConfig

def test_bfla_chain_generation():
    spec = {
        "paths": {
            "/admin/users": {
                "get": {
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "array"}}}}}
                }
            }
        }
    }
    builder = ChainBuilder(spec)
    chains = builder.build_chains()
    
    bfla_chains = [c for c in chains if c.variant == ChainVariant.BFLA]
    assert len(bfla_chains) == 1
    assert bfla_chains[0].attack.path == "/admin/users"

def test_mass_assignment_chain_generation():
    spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}},
                    "responses": {"201": {"content": {"application/json": {"schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}}
                }
            },
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path"}],
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}}
                }
            }
        }
    }
    builder = ChainBuilder(spec)
    chains = builder.build_chains()
    
    mass_chains = [c for c in chains if c.variant == ChainVariant.MASS_ASSIGNMENT]
    assert len(mass_chains) == 1
    assert mass_chains[0].attack.method == HttpMethod.POST

def test_verdict_bfla():
    engine = VerdictEngine()
    chain = AttackChain(
        chain_id="BFLA_1",
        resource_name="admin",
        source=ChainSource.BFLA_HEURISTIC,
        create=Endpoint("/admin", HttpMethod.GET),
        read=Endpoint("/admin", HttpMethod.GET),
        attack=Endpoint("/admin", HttpMethod.GET),
        variant=ChainVariant.BFLA
    )
    
    # Test CONFIRMED
    res1 = ChainResult(chain=chain, read_as_attacker_status=200)
    engine.evaluate(res1)
    assert res1.verdict == Verdict.CONFIRMED
    assert res1.score == 1.0

    # Test SECURE
    res2 = ChainResult(chain=chain, read_as_attacker_status=403)
    engine.evaluate(res2)
    assert res2.verdict == Verdict.SECURE
    
    # Test ERROR
    res3 = ChainResult(chain=chain, read_as_attacker_status=500)
    engine.evaluate(res3)
    assert res3.verdict == Verdict.ERROR

def test_verdict_mass_assignment():
    engine = VerdictEngine()
    chain = AttackChain(
        chain_id="MA_1",
        resource_name="user",
        source=ChainSource.LAYER1_PATH,
        create=Endpoint("/users", HttpMethod.POST),
        read=Endpoint("/users/{id}", HttpMethod.GET),
        attack=Endpoint("/users", HttpMethod.POST),
        variant=ChainVariant.MASS_ASSIGNMENT
    )
    
    # Test CONFIRMED (canary leaked)
    res1 = ChainResult(chain=chain, read_as_attacker_body={"id": 1, "is_admin": True})
    engine.evaluate(res1)
    assert res1.verdict == Verdict.CONFIRMED
    assert res1.score == 1.0

    # Test SECURE (canary not leaked)
    res2 = ChainResult(chain=chain, read_as_attacker_body={"id": 1, "is_admin": False})
    engine.evaluate(res2)
    assert res2.verdict == Verdict.SECURE
    assert res2.score == 0.0
