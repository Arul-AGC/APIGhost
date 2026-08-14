"""Tests for traffic importer."""

import json
import os
import tempfile
from apighost.importer import TrafficImporter

def test_import_har():
    har_content = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://api.test/users/123"
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "http://api.test/orders",
                        "postData": {
                            "text": '{"amount": 100}'
                        }
                    }
                }
            ]
        }
    }
    
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(har_content, f)
        temp_name = f.name
        
    try:
        importer = TrafficImporter()
        spec = importer.import_har(temp_name)
        
        # /users/123 should be normalized to /users/{param1}
        assert "/users/{param1}" in spec["paths"]
        assert "get" in spec["paths"]["/users/{param1}"]
        
        # /orders
        assert "/orders" in spec["paths"]
        assert "post" in spec["paths"]["/orders"]
        
        # Check body extraction
        req_body = spec["paths"]["/orders"]["post"].get("requestBody")
        assert req_body is not None
        assert req_body["content"]["application/json"]["schema"]["properties"]["amount"]["type"] == "integer"
    finally:
        os.unlink(temp_name)
