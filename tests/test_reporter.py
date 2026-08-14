"""Tests for multi-format reporter."""

import os
import tempfile
import json
from apighost.reporter import Reporter
from apighost.models import AttackChain, ChainResult, Endpoint, HttpMethod, ChainSource, Verdict, ChainVariant

def test_reporter_generation():
    # Setup dummy data
    create_ep = Endpoint(path="/api/orders", method=HttpMethod.POST)
    read_ep = Endpoint(path="/api/orders/{id}", method=HttpMethod.GET)
    chain = AttackChain(
        chain_id="CHAIN_001",
        resource_name="orders",
        source=ChainSource.LAYER1_PATH,
        create=create_ep,
        read=read_ep,
        variant=ChainVariant.READ
    )
    result = ChainResult(
        chain=chain,
        verdict=Verdict.CONFIRMED,
        score=0.9,
        read_as_attacker_status=200,
        signals={"status_match": 1.0},
        duration_ms=150,
        resource_id="123",
        create_status=201,
        read_as_owner_status=200,
        teardown_success=True
    )
    
    reporter = Reporter([result])
    
    # Test JSON
    json_out = reporter.generate_json()
    assert "CHAIN_001" in json_out
    assert "CONFIRMED" in json_out
    
    # Test HTML
    html_out = reporter.generate_html()
    assert "<!DOCTYPE html>" in html_out
    assert "CHAIN_001" in html_out
    assert "verdict-CONFIRMED" in html_out
    
    # Test MD
    md_out = reporter.generate_markdown()
    assert "# APIGhost Scan Report" in md_out
    assert "CHAIN_001" in md_out
    
    # Test SARIF
    sarif_out = reporter.generate_sarif()
    sarif_data = json.loads(sarif_out)
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "APIGhost"
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["level"] == "error"

def test_reporter_save():
    # Similar dummy data
    create_ep = Endpoint(path="/api/users", method=HttpMethod.POST)
    read_ep = Endpoint(path="/api/users/{id}", method=HttpMethod.GET)
    chain = AttackChain(
        chain_id="CHAIN_002",
        resource_name="users",
        source=ChainSource.LAYER1_PATH,
        create=create_ep,
        read=read_ep,
        variant=ChainVariant.READ
    )
    result = ChainResult(
        chain=chain, 
        verdict=Verdict.SECURE,
        score=0.0,
        signals={"status_mismatch": 1.0},
        duration_ms=100
    )
    
    reporter = Reporter([result])
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save HTML
        html_path = os.path.join(tmpdir, "report.html")
        reporter.save(html_path, "html")
        assert os.path.exists(html_path)
        with open(html_path) as f:
            assert "<!DOCTYPE html>" in f.read()
            
        # Save SARIF
        sarif_path = os.path.join(tmpdir, "report.sarif")
        reporter.save(sarif_path, "sarif")
        assert os.path.exists(sarif_path)
