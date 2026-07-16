# APIGhost: Stateful BOLA Detection Engine

## The Problem
Existing open-source DAST tools (ZAP, VulnAPI, Schemathesis) test API endpoints in isolation (stateless). They are architecturally incapable of detecting Broken Object Level Authorization (BOLA), the #1 API vulnerability, which requires a multi-step, stateful attack chain between two users (e.g., User A creates a resource, User B attempts to read it).

## The Solution
APIGhost is a pure-Python, automated, stateful attack chain generator that parses OpenAPI specifications, maps CRUD dependencies, and executes cross-user authorization boundary tests.

## Architecture & Components

### 1. Spec Parser (`parser.py`)
- **Technology:** `prance.ResolvingParser`
- **Purpose:** Loads the OpenAPI specification (YAML/JSON) and recursively resolves all `$ref` pointers (nested, circular, and external) into a flat Python dictionary. This ensures the engine operates on fully dereferenced schemas.

### 2. Chain Builder (`chain_builder.py`)
- **Technology:** Dual-Layer Resolution Algorithm
- **Purpose:** 
  - **Layer 1 (Path-Based):** Groups endpoints by RESTful base paths (e.g., `POST /orders` and `GET /orders/{id}`).
  - **Layer 2 (Schema-Based):** Matches POST response field names/types to GET parameter schemas to map producer-consumer relationships on non-RESTful routing.
- **Output:** A list of valid attack chains (`CREATE -> TEST -> TEARDOWN`).

### 3. Data Generator (`generator.py`)
- **Technology:** Three-Tier Value Resolution
- **Purpose:** Generates valid HTTP payloads to bypass input validation.
  - **Tier 1:** Uses spec-provided `example` values.
  - **Tier 2:** Uses heuristics based on `format` hints and property names.
  - **Tier 3 (Dependency Prefetch):** Scans the spec for foreign keys (e.g., `product_id`), calls the corresponding GET endpoint with User A's token, and harvests a real ID to inject into the POST body.

### 4. Network Engine & Executor (`executor.py`)
- **Technology:** `httpx` (async), `asyncio`
- **Purpose:** Executes the chains with WAF survival and state management.
  - **Resilience:** Implements a global token bucket, concurrency limits (Semaphore), and randomized jitter.
  - **Auth:** Supports preemptive token refresh mid-scan via a global lock.
  - **Teardown:** Uses a LIFO cleanup stack inside a `try/finally` block to delete resources with User A's token. If teardown fails (e.g., 429 backoff exhausted), it drops the task into a Dead Letter Queue (DLQ) for a final sweep at the end of the scan.

### 5. Verdict Engine (`verdict.py`)
- **Technology:** Multi-Signal Weighted Scoring (Jaccard Index)
- **Purpose:** Analyzes the response of User B attempting to access User A's resource.
  - Avoids false positives by not relying purely on `200 OK` status codes.
  - Computes a weighted score based on: Status Code, Structural Similarity (Jaccard Index on JSON keys), Value-Level Data Leakage, Error Keyword Penalty, and Content-Length Ratio.
  - Outputs a confidence verdict: CONFIRMED, LIKELY, POSSIBLE, or SECURE.

## Tech Stack
- **Language:** Python 3.12+
- **HTTP Client:** `httpx`
- **OpenAPI Parsing:** `prance`, `openapi-spec-validator`
- **CLI Framework:** `typer`, `rich`
- **Reporting:** `Jinja2`, `WeasyPrint` (PDF generation)
