# APIGhost Architecture

APIGhost is fundamentally different from standard DAST scanners and stateless fuzzers. It does not blindly fire payloads at endpoints. It builds a semantic understanding of the API's resources, constructs stateful execution chains, and evaluates authorization mathematically.

## 1. The Core Engine Loop

The engine operates in four distinct phases:

1. **Parse & Resolve**: Parses the OpenAPI spec, resolves `$ref` pointers, and infers endpoint CRUD roles (Create, Read, Update, Delete) based on HTTP methods and path structures.
2. **Chain Generation**: Links endpoints into stateful attack chains using a 3-layer heuristic matcher.
3. **Execution**: Fires the chains using two distinct authentication tokens (User A and User B) to simulate an attacker targeting a victim.
4. **Verdict Evaluation**: Compares the structural similarity of the attacker's response against the baseline (owner's) response to determine if an authorization flaw exists.

---

## 2. 3-Layer Chain Generation

An IDOR/BOLA vulnerability can only be proven if an attacker can manipulate a resource belonging to another user. To test this, APIGhost must first *create* a resource as the victim, extract its ID, and then attempt to *read/update* it as the attacker. 

The `ChainBuilder` generates these `CREATE -> READ` chains using three layers:

### Layer 1: Path-Based Grouping
Matches endpoints that share the same base REST path.
- `POST /api/orders` (Create)
- `GET /api/orders/{id}` (Read)

### Layer 2: Schema-Based Matching
If endpoints don't follow REST conventions (e.g., `POST /api/createOrder` and `GET /api/fetchOrder`), Layer 2 inspects the JSON schemas. It maps the output fields of a POST response to the path/query parameters of a GET request (e.g., `orderId -> orderId`).

### Layer 3: Dependency Prefetching
Some endpoints require foreign keys to create a resource (e.g., `POST /api/orders` requires a `productId`). During the execution phase, the `DataGenerator` intercepts the payload generation, searches the spec for a `GET /api/products` endpoint, executes it live against the target, extracts a valid `productId`, and injects it into the POST payload.

---

## 3. The Execution Flow

Every `AttackChain` follows a strict execution lifecycle in `executor.py`:

1. **Create (User A)**: Send the POST request using User A's token. Extract the primary key (e.g., `id=42`) from the response.
2. **Read as Owner (User A)**: Send the GET request (`/api/orders/42`) using User A's token. This establishes the baseline "Authorized Response".
3. **Read as Attacker (User B)**: Send the exact same GET request using User B's token.
4. **Teardown (User A)**: Delete the resource (`DELETE /api/orders/42`) to leave the target environment clean.

---

## 4. The Verdict Engine

APIGhost does not rely on naive status code matching (e.g., "If 200 OK, then Vulnerable"). APIs are notorious for returning `200 OK` with an empty body `{}`, or `200 OK` with an error message `{"error": "Unauthorized"}`.

The `VerdictEngine` computes a confidence score using multiple signals:
- **Status Code Match**: Did the attacker get the same HTTP status as the owner?
- **Structural Similarity**: Does the attacker's JSON response have the same key structure as the owner's?
- **Data Overlap**: Does the attacker's JSON response contain the same values as the owner's?

If the structure and data match, it mathematically proves that User B accessed User A's data, yielding a `CONFIRMED` BOLA vulnerability.
