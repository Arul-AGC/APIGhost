"""Tests for composite resource IDs in executor."""

from apighost.executor import ChainExecutor, ExecutorConfig
from unittest.mock import patch

def test_extract_multiple_ids():
    config = ExecutorConfig("http://test.local", "a", "b")
    with patch('apighost.executor.DataGenerator'), patch('apighost.executor.DependencyPrefetcher'):
        executor = ChainExecutor(config, {"paths": {}})
        
    body = {
        "org_id": "org_123",
        "data": {
            "user_id": "usr_456",
            "order_id": 789
        }
    }
    
    ids = executor._extract_resource_ids(body, ["org_id", "user_id", "order_id"])
    assert ids["org_id"] == "org_123"
    assert ids["user_id"] == "usr_456"
    assert ids["order_id"] == 789
