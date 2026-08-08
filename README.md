# 🔍 APIGhost

**Stateful BOLA Detection Engine — Cross-User Authorization Testing for REST APIs**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

Existing open-source DAST tools (OWASP ZAP, VulnAPI, Schemathesis) test API endpoints **in isolation**. They send a single request, analyze the response, and move on. This stateless approach is architecturally incapable of detecting **Broken Object Level Authorization (BOLA)** — the **#1 API vulnerability** ([OWASP API Security Top 10, 2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)).

BOLA requires a **multi-step, cross-user attack chain**:
1. **User A** creates a resource (e.g., an order)
2. **User B** attempts to access that resource using User A's resource ID
3. If User B succeeds → **BOLA vulnerability confirmed**

No single-request scanner can detect this.

## The Solution

APIGhost is a **pure-Python, automated, stateful attack chain generator** that:

1. **Parses** OpenAPI specifications and resolves all `$ref` pointers
2. **Maps** CRUD dependencies via a **Dual-Layer Producer-Consumer Resolution Algorithm**
3. **Generates** valid payloads using a **Three-Tier Value Resolution** system (not `{"name": "string"}`)
4. **Executes** cross-user authorization boundary tests with WAF-resilient networking
5. **Analyzes** results using a **Multi-Signal Weighted Verdict Engine** with Jaccard similarity

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  OpenAPI     │────▶│  Chain       │────▶│  Data        │
│  Spec Parser │     │  Builder     │     │  Generator   │
│  (prance)    │     │  (Dual-Layer)│     │  (3-Tier)    │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                     ┌──────────────┐     ┌───────▼───────┐
                     │  Verdict     │◀────│  Executor     │
                     │  Engine      │     │  (httpx async) │
                     │  (Jaccard)   │     │  Token Bucket  │
                     └──────────────┘     └───────────────┘
```

### Components

| Module | Purpose | Key Technology |
|--------|---------|----------------|
| `parser.py` | Resolves OpenAPI specs with all `$ref` pointers | `prance.ResolvingParser` |
| `chain_builder.py` | Maps CRUD dependencies via Dual-Layer Resolution | Path grouping + Schema matching |
| `generator.py` | Generates valid payloads to bypass input validation | Three-Tier: Examples → Heuristics → Prefetch |
| `executor.py` | Dual-token async HTTP engine with WAF resilience | `httpx`, Token Bucket, Semaphore, DLQ |
| `verdict.py` | Multi-signal BOLA verdict scoring | Jaccard Index on JSON key structures |
| `cli.py` | Rich terminal interface | `typer`, `rich` |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Arul-AGC/APIGhost.git
cd APIGhost

# Install in development mode (Python 3.12+ required)
pip install -e .
```

## Usage

### Discover Attack Chains (Dry Run)

```bash
apighost chains --spec path/to/openapi.yaml
```

This parses the spec and displays all discovered attack chains without making any HTTP requests.

### Full BOLA Scan

```bash
apighost scan \
  --spec path/to/openapi.yaml \
  --target http://localhost:8888 \
  --token-a "eyJ...user_a_token" \
  --token-b "eyJ...user_b_token" \
  --output report.json
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--spec`, `-s` | Path to OpenAPI spec (YAML/JSON) | Required |
| `--target`, `-t` | Base URL of target API | Required |
| `--token-a` | Bearer token for User A (owner) | Required |
| `--token-b` | Bearer token for User B (attacker) | Required |
| `--output`, `-o` | Report output path (JSON) | stdout |
| `--rate`, `-r` | Max requests/second | 10.0 |
| `--concurrent`, `-c` | Max concurrent requests | 5 |
| `--verbose`, `-v` | Debug logging | False |

---

## How It Works

### 1. Dual-Layer Chain Resolution

**Layer 1 (Path-Based):** Groups endpoints by RESTful base paths. Fast, handles ~80% of real APIs.
```
POST   /api/orders          → CREATE
GET    /api/orders/{id}     → READ (test)
DELETE /api/orders/{id}     → TEARDOWN
```

**Layer 2 (Schema-Based):** For non-RESTful APIs, matches POST response fields to GET parameter schemas.
```
POST /api/create-review → response: {"review_id": 42}
GET  /api/fetch-review?review_id=42
→ "review_id" in POST response matches "review_id" in GET params → Chain!
```

### 2. Three-Tier Value Resolution

| Tier | Source | Example |
|------|--------|---------|
| **Tier 1** | Spec `example` values | `"example": "john@example.com"` |
| **Tier 2** | Format hints + name heuristics | `format: email` → `user_abc@test.com` |
| **Tier 3** | Dependency Prefetch | `product_id` → calls `GET /products`, uses real ID |

### 3. Multi-Signal Verdict Engine

Does **NOT** rely on HTTP status codes alone. Uses 5 weighted signals:

| Signal | Weight | What It Measures |
|--------|--------|-----------------|
| Status Code | 0.30 | Same status for owner vs. attacker |
| Structural Similarity (Jaccard) | 0.35 | Same JSON key structure |
| Data Leakage | 0.20 | Same specific values leaked |
| Error Keywords | 0.10 | Denial phrases in response body |
| Content-Length Ratio | 0.05 | Similar response sizes |

**Verdict Thresholds:** CONFIRMED (≥0.75) · LIKELY (≥0.50) · POSSIBLE (≥0.25) · SECURE (<0.25)

---

## Testing

```bash
# Run chain builder tests
python tests/test_chain_builder.py

# Run all tests
python -m pytest tests/ -v
```

---

## Tech Stack

- **Language:** Python 3.12+
- **HTTP Client:** `httpx` (async)
- **OpenAPI Parsing:** `prance`, `openapi-spec-validator`
- **CLI:** `typer`, `rich`
- **Reporting:** `Jinja2` (HTML reports)

---

## Authors

- Arul Guru Chandiran
- Kapil
- Kishore
- Roopesh

---

## License

MIT License — see [LICENSE](LICENSE) for details.
