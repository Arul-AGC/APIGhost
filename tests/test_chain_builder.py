"""
Test script for the Chain Builder — Dual-Layer Resolution.

Verifies:
1. Layer 1 catches RESTful endpoints (orders, users)
2. Layer 2 catches non-RESTful endpoints (create-review / fetch-review)
3. ID field inference works correctly
4. Resource names are extracted properly
"""

import json
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from apighost.chain_builder import ChainBuilder, build_chains_from_spec
from apighost.models import ChainSource

logging.basicConfig(
    level=logging.INFO,
    format="%(name)s | %(levelname)s | %(message)s"
)


def main():
    # Load the test spec (already resolved — no $refs to chase)
    spec_path = Path(__file__).parent / "test_spec.json"
    with open(spec_path) as f:
        spec = json.load(f)

    print("=" * 60)
    print("  APIGhost Chain Builder — Dual-Layer Resolution Test")
    print("=" * 60)

    # Build chains
    builder = ChainBuilder(spec)
    chains = builder.build_chains()

    print(f"\n📊 Endpoints extracted: {len(builder.endpoints)}")
    print(f"🔗 Attack chains discovered: {len(chains)}\n")

    # Display each chain
    for chain in chains:
        layer = "🟢 Layer 1 (Path)" if chain.source == ChainSource.LAYER1_PATH else "🟡 Layer 2 (Schema)"
        print(f"{'─' * 55}")
        print(f"  {layer}")
        print(f"  Chain ID:      {chain.chain_id}")
        print(f"  Resource:      {chain.resource_name}")
        print(f"  ID Field:      {chain.id_field}")
        print(f"  Confidence:    {chain.confidence:.0%}")
        print(f"  CREATE:        POST {chain.create.path}")
        print(f"  TEST (READ):   GET  {chain.read.path}")
        if chain.delete:
            print(f"  TEARDOWN:      DELETE {chain.delete.path}")
        else:
            print(f"  TEARDOWN:      ⚠️  No DELETE endpoint found")
        print()

    print(f"{'─' * 55}")

    # Validate expected results
    layer1_chains = [c for c in chains if c.source == ChainSource.LAYER1_PATH]
    layer2_chains = [c for c in chains if c.source == ChainSource.LAYER2_SCHEMA]

    print("\n✅ Validation:")
    print(f"   Layer 1 chains: {len(layer1_chains)} (expected: 2 — orders, users)")
    print(f"   Layer 2 chains: {len(layer2_chains)} (expected: 1 — reviews)")

    # Check that orders chain has DELETE for teardown
    orders_chains = [c for c in chains if c.resource_name == "orders"]
    if orders_chains and orders_chains[0].delete:
        print(f"   Orders teardown: ✅ DELETE {orders_chains[0].delete.path}")
    else:
        print(f"   Orders teardown: ❌ Missing!")

    # Check review chain was caught by Layer 2
    review_chains = [c for c in layer2_chains if "review" in c.resource_name.lower()]
    if review_chains:
        print(f"   Review (Layer 2): ✅ Linked via '{review_chains[0].id_field}'")
    else:
        print(f"   Review (Layer 2): ❌ Not matched!")

    print()


if __name__ == "__main__":
    main()


import pytest

class TestChainVariants:
    """Test that chain builder emits UPDATE and DELETE chain variants."""

    def test_update_chain_discovered(self):
        """Verify UPDATE chain is discovered when PUT endpoint exists."""
        from apighost.chain_builder import ChainBuilder
        from apighost.models import ChainVariant
        import json
        
        with open("tests/test_spec.json") as f:
            spec = json.load(f)
        
        builder = ChainBuilder(spec)
        chains = builder.build_chains()
        
        update_chains = [c for c in chains if c.variant == ChainVariant.UPDATE]
        assert len(update_chains) > 0, "Should discover at least one UPDATE chain"
        
        for chain in update_chains:
            assert chain.attack is not None
            assert chain.attack.method.value in ("PUT", "PATCH")

    def test_delete_chain_discovered(self):
        """Verify DELETE chain is discovered when DELETE endpoint exists."""
        from apighost.chain_builder import ChainBuilder
        from apighost.models import ChainVariant
        import json
        
        with open("tests/test_spec.json") as f:
            spec = json.load(f)
        
        builder = ChainBuilder(spec)
        chains = builder.build_chains()
        
        delete_chains = [c for c in chains if c.variant == ChainVariant.DELETE]
        assert len(delete_chains) > 0, "Should discover at least one DELETE chain"

    def test_read_chains_still_exist(self):
        """Verify original READ chains are still generated."""
        from apighost.chain_builder import ChainBuilder
        from apighost.models import ChainVariant
        import json
        
        with open("tests/test_spec.json") as f:
            spec = json.load(f)
        
        builder = ChainBuilder(spec)
        chains = builder.build_chains()
        
        read_chains = [c for c in chains if c.variant == ChainVariant.READ]
        assert len(read_chains) >= 2, "Should still have at least 2 READ chains"
