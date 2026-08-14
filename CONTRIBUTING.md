# Contributing to APIGhost

We love pull requests. APIGhost is built to be modular, extensible, and hacker-friendly. Whether you're adding a new WAF bypass technique, expanding the payload generator, or writing tests, your contributions are welcome.

## Development Setup

APIGhost uses `poetry` for dependency management.

1. **Clone the repo:**
   ```bash
   git clone https://github.com/Arul-AGC/APIGhost.git
   cd APIGhost
   ```

2. **Install dependencies:**
   ```bash
   poetry install
   ```

3. **Run tests:**
   ```bash
   python -m pytest tests/ -v
   ```

## Architecture Overview
Before diving into the code, please read the [Architecture Guide](docs/ARCHITECTURE.md). Understanding the 3-Layer Chain Builder and the Dual-Token Execution model is critical for adding new vulnerability checks.

## How to Add a New Vulnerability Check

APIGhost's modular engine makes it easy to add new attack vectors.

1. **Define the Variant**: Add your new vulnerability class to the `ChainVariant` enum in `src/apighost/models.py`.
2. **Build the Chain**: Update `src/apighost/chain_builder.py` to instruct the engine on when to emit your new `ChainVariant`.
3. **Execute the Payload**: Add your injection or bypass logic to the `execute_all()` loop in `src/apighost/executor.py`.
4. **Evaluate the Verdict**: If your attack requires a custom verification check (e.g., searching for a specific string in the response body), add it to `src/apighost/verdict.py`. Otherwise, the default structural similarity engine will handle it.

## Pull Request Guidelines

- **Keep it focused**: One vulnerability class or bug fix per PR. Don't submit massive refactors without opening an issue first.
- **Write tests**: If you add a new vulnerability check, write a mock FastAPI endpoint in `tests/` to prove it works.
- **No breaking changes**: Ensure `apighost scan --help` still works as expected.

## Code Style

- APIGhost uses Python 3.12+ features (like `match/case` and modern type hinting). 
- We don't enforce a strict linter in CI yet, but please keep your code PEP8 compliant and use type hints for all function signatures.

Happy Hunting.
