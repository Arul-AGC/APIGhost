import logging
from typing import Dict, Any
from pathlib import Path
import prance

logger = logging.getLogger(__name__)

class SpecParserError(Exception):
    pass

class SpecParser:
    """
    Parses and completely dereferences an OpenAPI specification using prance.
    Resolves all nested, external, and circular $ref pointers into a flat dictionary.
    """
    def __init__(self, spec_path: str | Path):
        self.spec_path = str(spec_path)
        self.raw_spec: Dict[str, Any] = {}
        self.resolved_spec: Dict[str, Any] = {}

    def parse(self) -> Dict[str, Any]:
        """
        Parses the OpenAPI specification and returns the fully resolved dictionary.
        """
        try:
            logger.info(f"Loading and resolving OpenAPI spec from {self.spec_path}")
            # prance.ResolvingParser automatically loads and fully resolves $refs.
            parser = prance.ResolvingParser(self.spec_path, strict=False)
            self.resolved_spec = parser.specification
            
            if "paths" not in self.resolved_spec:
                raise SpecParserError("Invalid OpenAPI spec: 'paths' field is missing.")
                
            logger.info(f"Successfully resolved spec. Extracted {len(self.resolved_spec['paths'])} paths.")
            return self.resolved_spec
            
        except prance.ValidationError as e:
            logger.error(f"OpenAPI Validation Error: {str(e)}")
            raise SpecParserError(f"Validation failed: {str(e)}") from e
        except Exception as e:
            logger.error(f"Failed to parse OpenAPI spec: {str(e)}")
            raise SpecParserError(f"Parse error: {str(e)}") from e

    def get_endpoints(self) -> list[dict]:
        """
        Flattens the spec paths into a list of endpoint dictionaries for easier processing.
        """
        endpoints = []
        if not self.resolved_spec:
            return endpoints
            
        for path, methods in self.resolved_spec.get("paths", {}).items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "details": details
                })
        return endpoints

if __name__ == "__main__":
    # Simple test logic
    logging.basicConfig(level=logging.INFO)
    # create a dummy spec to test if we can import
    print("Parser module ready.")
