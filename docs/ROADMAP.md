# aiows — Production Roadmap

This document outlines the phased implementation plan to bring **aiows** to a
stable, production-ready state. Each phase must be completed and reviewed before
the next one begins. No time estimates are given — quality over speed.

---

## Phase 1 — Critical Bug Fixes & Stability

> Goal: eliminate known defects that make the framework unsafe to run in
> production.

### 1.1 Fix race conditions in connection management

- Audit all shared mutable state in `WebSocketServer` and `WebSocket`
- Replace unsafe reads/writes with proper `asyncio.Lock` or `asyncio.Event`
  guards
- Add regression tests that reproduce each race condition before fixing it

### 1.2 Optimize WebSocket send/receive locks

- Profile lock contention under concurrent load
- Replace coarse-grained locks with fine-grained equivalents where possible
- Ensure backpressure queue operations are fully lock-safe
- Verify that slow-client disconnect logic does not deadlock

### 1.3 Simplify middleware execution chain

- Replace the current closure-based `next_handler` pattern with a cleaner,
  explicit chain object
- Ensure middleware short-circuit (early exit) works correctly for all error
  categories
- Add unit tests for every combination of middleware ordering

### 1.4 Harden error handling consistency

- Audit every `except` block in dispatcher, server, and websocket modules
- Guarantee that `FATAL` errors always close the connection
- Guarantee that `CLIENT_ERROR` never crashes the server loop
- Normalize error response payloads sent back to clients

---

## Phase 2 — Core Missing Features

> Goal: implement the two most-requested capabilities absent from the current
> codebase.

### 2.1 Broadcasting system

- Implement `server.broadcast(message)` — send to all connected clients
- Implement `server.broadcast_to(filter_fn, message)` — send to a subset
- Implement `websocket.broadcast_except_self(message)` — convenience method
- Thread-safe iteration over the live connection set
- Tests covering broadcast under concurrent connect/disconnect

### 2.2 Rooms / Channels system

New module: `aiows/rooms.py`

- `RoomManager` — singleton attached to the server instance
- `Room` class:
  - `join(websocket)` / `leave(websocket)`
  - `broadcast(message)` — send to all room members
  - `members` — read-only property returning current member set
  - `size` — number of current members
- Router-level decorators:
  - `@router.message("join")` auto-integration with `JoinRoomMessage`
- `RoomMiddleware` (optional) — attach room context to each connection
- Full test suite: join, leave, broadcast, concurrent access, empty room edge
  cases

### 2.3 Complete LoggingMiddleware

- Finish the implementation referenced in `middleware/logging.py`
- Log: connection open/close, message type, message size, processing duration,
  errors
- Support structured logging (JSON output) for log aggregators (Loki, Datadog,
  etc.)
- Make log level configurable via `AiowsSettings`

---

## Phase 3 — Developer Experience & Documentation

> Goal: make the project welcoming and self-explanatory for external
> contributors and users.

### 3.1 API Reference

New file: `docs/api/`

- `server.md` — `WebSocketServer` public API
- `router.md` — `Router`, decorators, sub-router composition
- `middleware.md` — built-in middleware, how to write custom middleware
- `rooms.md` — `RoomManager`, `Room` API (added in Phase 2)
- `exceptions.md` — error hierarchy and when each type is raised
- `validators.md` — available validators and how to extend them
- `types.md` — built-in message types and how to define custom ones

### 3.2 Guides

New files: `docs/guides/`

- `getting-started.md` — end-to-end from install to first running server
- `authentication.md` — token flow, custom auth, IP whitelisting
- `rooms-and-broadcasting.md` — practical room patterns
- `production-deployment.md` — SSL, reverse proxy (nginx), systemd, Docker
- `writing-middleware.md` — step-by-step custom middleware tutorial
- `security.md` — threat model, what aiows protects against and what it does
  not

### 3.3 CONTRIBUTING.md

- Development environment setup
- Code style rules (Black + isort + mypy strict)
- How to run the test suite
- Pull request checklist
- Issue labels and triage process

### 3.4 CHANGELOG.md

- Adopt [Keep a Changelog](https://keepachangelog.com) format
- Document all changes from `0.1.0` through current version
- Establish the release tagging convention (semver)

### 3.5 Improve examples

- Add `examples/rooms_chat.py` — multi-room chat using Phase 2 rooms API
- Add `examples/broadcast_ticker.py` — live data feed with broadcasting
- Add `examples/custom_middleware.py` — demonstrates writing a middleware from
  scratch
- Ensure every example has a matching HTML client in `examples/`

---

## Phase 4 — Performance & Benchmarking

> Goal: measure, document, and optimize throughput before calling the framework
> production-ready.

### 4.1 Benchmarking suite

New directory: `benchmarks/`

- `bench_throughput.py` — messages per second, single client and N clients
- `bench_broadcast.py` — time to deliver broadcast to 100 / 1 000 / 10 000
  clients
- `bench_middleware.py` — overhead introduced by each middleware layer
- `bench_rooms.py` — room join/leave/broadcast under load
- Include a `README.md` inside `benchmarks/` explaining how to run and
  interpret results

### 4.2 Connection pooling

- Investigate and implement connection pool for server-side outbound connections
  (where aiows acts as a client or relay)
- Document the use case and API clearly

### 4.3 Hot path optimization

- Profile dispatcher message routing under load
- Reduce per-message allocations in `WebSocket.receive_json` /
  `send_json`
- Investigate `uvloop` as an optional drop-in event loop for higher throughput
- Document `uvloop` integration in `docs/guides/production-deployment.md`

---

## Phase 5 — Production Hardening & Release

> Goal: ship a stable `1.0.0` that the community can depend on.

### 5.1 CI/CD pipeline

New directory: `.github/workflows/`

- `ci.yml`:
  - Run on every PR: lint (Black, isort, mypy), full test suite, Python
    3.8 – 3.13 matrix
- `release.yml`:
  - Triggered on tag push (`v*`)
  - Build wheel + sdist
  - Publish to PyPI via trusted publisher (OIDC)
  - Create GitHub Release with auto-generated notes

### 5.2 Security audit

- Review all token/HMAC logic in `AuthMiddleware` against OWASP recommendations
- Review JSON bomb protector limits against real-world payloads
- Ensure no sensitive data (tokens, IPs) is ever written to logs in plain text
- Add `SECURITY.md` with responsible disclosure policy

### 5.3 Bump to stable

- Update `pyproject.toml`: `version = "1.0.0"`, classifier
  `Development Status :: 5 - Production/Stable`
- Tag `v1.0.0` in git
- Publish to PyPI

---

## Guiding Principles

These principles apply across all phases:

1. **No breaking changes without a deprecation cycle** — mark old APIs with
   `DeprecationWarning` for at least one minor version before removal.
2. **Every new feature ships with tests** — no feature is merged without a
   corresponding test file.
3. **Every public API is documented** — no undocumented public symbols.
4. **Security over convenience** — when a trade-off exists, choose the safer
   default and allow opt-out via configuration.
5. **Backward compatibility** — the `aiogram`-inspired interface (Router,
   decorators, Middleware) must remain stable throughout all phases.
