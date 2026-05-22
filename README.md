# Progressive Server

**Matrix homeserver written in C++23** — built from scratch for the Matrix ecosystem.

[![CI](https://github.com/progressive-chat/progressive-server/actions/workflows/ci.yml/badge.svg)](https://github.com/progressive-chat/progressive-server/actions/workflows/ci.yml)

## Overview

Progressive Server is a high-performance Matrix homeserver implemented in modern C++23. It is built from the ground up, using **Synapse** as the primary architectural reference, with plans to also draw from **Dendrite**, **Conduit**, and other Matrix implementations.

### Why C++?

- **Zero-runtime-overhead abstractions** — templates, constexpr, move semantics
- **No garbage collection** — deterministic memory management
- **Direct kernel I/O** — epoll/kqueue via Boost.Asio
- **Single binary deployment** — static linking, minimal dependencies

## Current Status

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **Types** | Done | Domain-specific strings, Requester, StateMap, StreamToken |
| **Config** | Done | JSON config loading, validation, listener/database setup |
| **Events** | Done | Event model, UnsignedData, Signatures, factory |
| **JSON** | Done | Canonical JSON, nlohmann integration |
| **Storage** | Done | SQLite3 + PostgreSQL backends, connection pool, schema DDL |
| **HTTP Server** | Done | Boost.Beast TCP acceptor, session handling, keep-alive |
| **Router** | Done | Regex URL routing, path params, CORS, JSON responses |
| **Auth** | Done | SHA-256 passwords, access tokens, registration |
| **Client/Server API** | Done | /versions, /login, /register, /whoami, /createRoom, /sync |
| **Federation** | Done | /send, /event, /state, /make_join, /send_join, /query, X-Matrix auth |
| **Key Server** | Done | /_matrix/key/v2/server |
| **State Resolution** | Done | V1 (phase-ordered) + V2 (iterative auth checks, topological sort) |
| **Room Versions** | Done | v1–v11 with auth properties |
| **Push Rules** | Done | 26 base rules, glob matcher, evaluator |
| **Auth Rules** | Done | `auth_types_for_event`, `check_state_dependent_auth_rules` |
| **Ed25519** | Stub | Signing infrastructure in place, real EVP signing pending |
| **Media** | Pending | Upload/download endpoints |
| **E2EE** | Pending | Key backup, device management |

## Building

### Prerequisites

- CMake 3.22+
- C++23 compiler (GCC 14+, Clang 18+)
- Boost 1.84+ (URL, JSON)
- OpenSSL 3+
- SQLite3 or PostgreSQL

### Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run

```bash
# Generate config
./build/src/progressive-server --generate-config > homeserver.yaml

# Start server
./build/src/progressive-server -c homeserver.yaml
```

### Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPROGRESSIVE_BUILD_TESTS=ON
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

## Architecture

```
Client ──HTTP──> Beast Acceptor ──> Router ──> REST Servlets
                                                   │
                                          ┌────────┼────────┐
                                          ▼        ▼        ▼
                                        Auth    Storage   Federation
                                          │        │        │
                                          └────────┼────────┘
                                                   ▼
                                            SQLite / PostgreSQL
```

### Stack

- **I/O**: Boost.Asio + Boost.Beast (HTTP/1.1)
- **JSON**: nlohmann/json
- **Crypto**: OpenSSL
- **Database**: SQLite3 (dev/test), PostgreSQL (production)
- **Build**: CMake + Ninja
- **CI**: GitHub Actions — Ubuntu 24.04/latest, macOS, Clang 18-20

## References

Built with architectural reference from:

- [Synapse](https://github.com/element-hq/synapse) — the reference Matrix homeserver (Python)
- [Dendrite](https://github.com/matrix-org/dendrite) — second-generation Matrix homeserver (Go)
- [Conduit](https://gitlab.com/famedly/conduit) — lightweight Matrix homeserver (Rust)

## License

To be determined. Currently all rights reserved.
