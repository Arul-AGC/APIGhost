# Supported Vulnerabilities & Bypasses

APIGhost currently tests for 6 classes from the OWASP API Top 10 (2023). This document outlines how the engine executes each test and the bypasses it attempts when initial tests fail.

---

## 1. BOLA / IDOR (Broken Object Level Authorization)
**API1:2023**

BOLA occurs when an endpoint relies on client-provided IDs to fetch or modify resources without validating that the requesting user owns that resource.

### The Attack Flow
1. **User A** creates a resource (`POST /api/orders`) -> gets `id=42`.
2. **User B** (Attacker) attempts to read (`GET /api/orders/42`).
3. If the server returns the exact same data structure and values to User B, it's vulnerable.

### Advanced Bypasses Attempted
If the standard request gets blocked (e.g., `403 Forbidden`), APIGhost automatically executes bypass chains:
- **HTTP Parameter Pollution (HPP)**: Injects multiple parameters to trick the validation middleware.
  - `GET /api/orders?id=<fake_id>&id=<real_id>`
- **Array Wrapping**: Exploits weak type coercion in modern frameworks (like Express.js).
  - `POST /api/orders` with body `{"order_id": [42]}`

---

## 2. BFLA (Broken Function Level Authorization)
**API5:2023**

BFLA occurs when regular users can access administrative or privileged endpoints.

### The Attack Flow
APIGhost scans the OpenAPI tags and paths to identify privileged endpoints (e.g., endpoints tagged with "admin" or containing `/internal/`). It then attempts to hit these endpoints using a standard, unprivileged user token.

### WAF & Reverse Proxy Bypasses
Many admin endpoints are protected by IP whitelists at the proxy level (Nginx/HAProxy) rather than application logic. APIGhost automatically injects spoofing headers to bypass these controls:
- `X-Forwarded-For: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Custom-IP-Authorization: 127.0.0.1`

---

## 3. Mass Assignment
**API3:2023**

Mass Assignment occurs when an API binds client payload data directly to underlying backend objects without whitelisting editable properties, allowing attackers to overwrite sensitive fields.

### The Attack Flow
During an `UPDATE` chain (PUT/PATCH), APIGhost injects "canary" fields into the JSON payload (e.g., `{"is_admin": true, "balance": 999999}`). 
It then issues a `READ` request. If the canary values appear in the subsequent read response, the endpoint is vulnerable to mass assignment.

*Note: Canary values are fully customizable via the `--canaries` CLI flag.*

---

## 4. Excessive Data Exposure
**API3:2019**

Excessive Data Exposure occurs when developers rely on the client (frontend app) to filter sensitive data out of the JSON response, rather than filtering it on the backend.

### The Attack Flow
APIGhost compares the actual JSON keys returned in a `200 OK` response against the declared keys in the OpenAPI schema. If the response contains undocumented keys (e.g., a hidden `password_hash` or `ssn` field), the engine flags it. 
*The schema extractor uses memory-safe object tracking to prevent infinite recursion on self-referencing API schemas.*

---

## 5. Rate Limiting / Unrestricted Resource Consumption
**API4:2023**

If an API does not enforce execution limits, it is vulnerable to brute-force attacks and DoS.

### The Attack Flow
APIGhost targets sensitive endpoints (`/login`, `/auth`, `/token`) and blasts them with concurrent requests. If the API fails to return a `429 Too Many Requests` status code within the burst limit, the endpoint is flagged.

*Note: The concurrent burst size is adjustable via the `--burst` CLI flag to accommodate high-capacity WAFs.*

---

## 6. Server-Side Injection
**API8:2023**

APIs that fail to sanitize input are vulnerable to backend injection attacks.

### The Attack Flow
APIGhost intercepts all string parameters in the payload generator and appends polyglot payloads designed to trigger SQLi or Template Injection (SSTI).
- **Payload**: `' OR 1=1-- {{7*7}}`
- **Verdict Engine**: Looks for HTTP 500s, leaked SQL syntax errors, or the evaluated mathematical result (`49`) in the response body.
