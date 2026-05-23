# Contributing to Progressive Server

## Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPROGRESSIVE_BUILD_TESTS=ON
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

## Code Style

- C++23, `clang-format --style=file` (Google-based, 2-space indent, 100 cols)
- `.hpp` for headers, `.cpp` for implementation
- Namespaces: `progressive::` with sub-namespaces per module

## Architecture

```
src/progressive/
├── types/       Domain types (UserID, RoomID, EventID)
├── config/      YAML/JSON config loading
├── events/      Event model, factory
├── json/        Canonical JSON
├── crypto/      Ed25519 signing (OpenSSL EVP)
├── storage/     DatabasePool, SQLite3/PostgreSQL, schema migrations
├── http/        Boost.Beast server + URL router
├── auth/        Access tokens, event authorization
├── rest/        Client/Server API (endpoints)
│   ├── client/  Matrix C-S API servlets
│   └── key/     Key server endpoints
├── federation/  Federation protocol (server + client + sender)
├── state/       State resolution (v1 + v2), room versions
├── push/        Push rule engine, glob matcher
├── ratelimit/   Token bucket rate limiter
├── media/       Media upload/download
└── util/        Random tokens, time helpers, logging
```

## Testing

- Unit tests: `tests/` with GoogleTest (`test_*.cpp`)
- Integration: `tests/integration.sh` — curl-based E2E against live server
- Run: `ctest --output-on-failure`

## CI

GitHub Actions: Ubuntu 24.04/latest, macOS, Clang 18-20, PostgreSQL service.
All 9 jobs must pass on every push.
