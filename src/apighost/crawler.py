import asyncio
import httpx
import json
import logging
import random
from typing import Dict, Any

logger = logging.getLogger(__name__)

class APICrawler:
    """
    Spec-less auto-discovery crawler for APIs.
    Discovers endpoints by brute-forcing a wordlist against a base URL
    and infers an OpenAPI-like spec from the responses.
    """
    def __init__(self, base_url: str, wordlist: list[str], concurrent: int = 10, delay: float = 0.1, token: str = None, auth_mode: str = "bearer", auth_header: str = "Authorization"):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist
        self.discovered_paths = {}
        self.concurrent = concurrent
        self.delay = delay
        self.token = token
        self.auth_mode = auth_mode
        self.auth_header = auth_header
        self.semaphore = asyncio.Semaphore(self.concurrent)

    def _get_auth_headers(self) -> dict:
        if not self.token:
            return {}
        if self.auth_mode == "bearer":
            return {self.auth_header: f"Bearer {self.token}"}
        return {self.auth_header: self.token}

    async def crawl(self) -> Dict[str, Any]:
        """
        Executes the crawl.
        """
        logger.info(f"Starting crawl on {self.base_url} with {len(self.wordlist)} words")
        async with httpx.AsyncClient(verify=False) as client:
            tasks = []
            for word in self.wordlist:
                tasks.append(self._check_path(client, word))
            
            await asyncio.gather(*tasks)

        # Build OpenAPI-like spec
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Crawled API Spec",
                "version": "1.0.0"
            },
            "paths": {}
        }
        
        for path, methods in self.discovered_paths.items():
            spec["paths"][path] = methods
            
        return spec

    async def _check_path(self, client: httpx.AsyncClient, word: str):
        path = f"/{word}"
        url = f"{self.base_url}{path}"
        headers = self._get_auth_headers()
        
        async with self.semaphore:
            await asyncio.sleep(random.uniform(0, self.delay))
            # Test GET
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code in (200, 401, 403, 405):
                    self._register_endpoint(path, "GET", resp)
                    
                # Smart pathing
                if resp.status_code in (200, 201):
                    for id_val in ["1", "test-uuid"]:
                        sub_path = f"{path}/{id_val}"
                        sub_url = f"{self.base_url}{sub_path}"
                        await asyncio.sleep(random.uniform(0, self.delay))
                        try:
                            sub_resp = await client.get(sub_url, headers=headers)
                            if sub_resp.status_code in (200, 201, 401, 403):
                                abs_path = f"{path}/{{id}}"
                                self._register_endpoint(abs_path, "GET", sub_resp)
                        except Exception as e:
                            logger.debug(f"Error GET {sub_url}: {e}")

            except Exception as e:
                logger.debug(f"Error GET {url}: {e}")

            # Test POST
            try:
                await asyncio.sleep(random.uniform(0, self.delay))
                resp = await client.post(url, json={}, headers=headers)
                if resp.status_code in (200, 201, 400, 401, 403, 405, 415, 422):
                    self._register_endpoint(path, "POST", resp)
            except Exception as e:
                logger.debug(f"Error POST {url}: {e}")

    def _register_endpoint(self, path: str, method: str, response: httpx.Response):
        if path not in self.discovered_paths:
            self.discovered_paths[path] = {}
            
        method_lower = method.lower()
        if method_lower in self.discovered_paths[path]:
            return
            
        details = {
            "summary": f"Discovered {method} endpoint",
            "responses": {
                str(response.status_code): {
                    "description": f"Observed status {response.status_code}"
                }
            }
        }
        
        # Infer response schema if 200/201 and JSON
        if response.status_code in (200, 201):
            try:
                body = response.json()
                if isinstance(body, dict):
                    schema = {"type": "object", "properties": {}}
                    for k, v in body.items():
                        if isinstance(v, str):
                            schema["properties"][k] = {"type": "string"}
                        elif isinstance(v, int):
                            schema["properties"][k] = {"type": "integer"}
                        elif isinstance(v, bool):
                            schema["properties"][k] = {"type": "boolean"}
                    details["responses"][str(response.status_code)]["content"] = {
                        "application/json": {
                            "schema": schema
                        }
                    }
            except Exception:
                pass
                
        self.discovered_paths[path][method_lower] = details
