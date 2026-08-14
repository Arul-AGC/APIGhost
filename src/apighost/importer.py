"""
APIGhost Importer

Converts HAR files and Burp Suite XML logs into an internal API spec
that the ChainBuilder can process.
"""

import json
import xml.etree.ElementTree as ET
import urllib.parse
import re
from typing import Any
import logging

logger = logging.getLogger(__name__)

class TrafficImporter:
    """Parses traffic dumps into an internal OpenAPI-like spec."""
    
    def __init__(self):
        self.spec = {
            "openapi": "3.0.0",
            "info": {"title": "APIGhost Auto-Generated Spec", "version": "1.0.0"},
            "paths": {}
        }
        
    def _add_endpoint(self, method: str, url: str, body: str | None = None) -> None:
        """Add an endpoint to the internal spec."""
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        method = method.lower()
        
        # Super basic dynamic parameter inference:
        # Convert /api/users/123 to /api/users/{param1}
        # This is a naive implementation; real tools use clustering.
        parts = path.split('/')
        new_parts = []
        path_params = []
        param_counter = 1
        
        for part in parts:
            if not part:
                continue
            # If it looks like an ID (digits, UUID, long hash)
            if re.match(r'^\d+$', part) or re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', part) or (len(part) > 16 and re.match(r'^[a-fA-F0-9]+$', part)):
                param_name = f"param{param_counter}"
                new_parts.append(f"{{{param_name}}}")
                path_params.append(param_name)
                param_counter += 1
            else:
                new_parts.append(part)
                
        canonical_path = "/" + "/".join(new_parts)
        
        if canonical_path not in self.spec["paths"]:
            self.spec["paths"][canonical_path] = {}
            
        if method not in self.spec["paths"][canonical_path]:
            endpoint_data = {
                "operationId": f"auto_{method}_{canonical_path.replace('/', '_').replace('{', '').replace('}', '')}",
                "parameters": [{"name": p, "in": "path"} for p in path_params],
                "responses": {"200": {"content": {"application/json": {"schema": {}}}}}
            }
            
            # If we have a JSON response body, we could infer its schema
            # For this basic implementation, we just assume it might have ID fields
            # The ChainBuilder Layer 2 handles ID inference from actual payloads during execution
            
            # If POST/PUT/PATCH, infer request body schema from the traffic body
            if method in ("post", "put", "patch") and body:
                try:
                    parsed_body = json.loads(body)
                    properties = {}
                    for k, v in parsed_body.items():
                        if isinstance(v, int):
                            properties[k] = {"type": "integer"}
                        elif isinstance(v, str):
                            properties[k] = {"type": "string"}
                        elif isinstance(v, bool):
                            properties[k] = {"type": "boolean"}
                    
                    if properties:
                        endpoint_data["requestBody"] = {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": properties
                                    }
                                }
                            }
                        }
                except (json.JSONDecodeError, AttributeError):
                    pass
                    
            self.spec["paths"][canonical_path][method] = endpoint_data

    def import_har(self, filepath: str) -> dict[str, Any]:
        """Parse a HAR file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
            
        entries = har_data.get("log", {}).get("entries", [])
        for entry in entries:
            req = entry.get("request", {})
            method = req.get("method")
            url = req.get("url")
            
            # Extract POST data if present
            body = None
            post_data = req.get("postData")
            if post_data:
                body = post_data.get("text")
                
            if method and url:
                self._add_endpoint(method, url, body)
                
        return self.spec

    def import_burp_xml(self, filepath: str) -> dict[str, Any]:
        """Parse a Burp Suite XML state file."""
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        for item in root.findall('item'):
            method_elem = item.find('method')
            url_elem = item.find('url')
            req_elem = item.find('request')
            
            if method_elem is not None and url_elem is not None:
                method = method_elem.text
                url = url_elem.text
                body = None
                
                # Try to extract body from raw request
                if req_elem is not None and req_elem.text:
                    import base64
                    try:
                        # Burp XML often base64 encodes the request
                        if req_elem.get('base64') == 'true':
                            raw_req = base64.b64decode(req_elem.text).decode('utf-8', errors='ignore')
                        else:
                            raw_req = req_elem.text
                            
                        # Split headers and body
                        parts = raw_req.split('\r\n\r\n', 1)
                        if len(parts) > 1:
                            body = parts[1]
                    except Exception:
                        pass
                        
                self._add_endpoint(method, url, body)
                
        return self.spec
