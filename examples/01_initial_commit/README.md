# Step 1 — Conduit's initial commit, translated to C++

Source of the translation: [`timokoesters/conduit@6264628c`](https://github.com/timokoesters/conduit/commit/6264628c113188af3a69ec16dcc4401884d95868)
— "Initial commit", 2020-02-15. This is commit zero of the entire Rust line of
Matrix homeservers: everything downstream (conduwuit → tuwunel / continuwuity)
grew from these ~90 lines.

The original was a [Rocket](https://rocket.rs) web app with a single stub
endpoint. The C++ translation keeps the file structure 1:1 but writes out what
the framework hid, using only the C++23 standard library and POSIX sockets —
zero dependencies.

## Files

| Conduit (Rust)            | This directory        | What it does |
|---------------------------|-----------------------|--------------|
| `src/main.rs`             | `main.cpp`            | Route handler + HTTP server loop |
| `src/ruma_wrapper.rs`     | `ruma_wrapper.hpp/cpp`| `Ruma<T>` body extractor + request/response types |
| `Cargo.toml`              | `CMakeLists.txt`      | Build |

## Concept map

| Rust world | C++ translation here |
|---|---|
| Rocket `#[post("/_matrix/client/r0/register")]` | `if req.method == "POST" && req.path == ...` in the accept loop |
| `routes![register_route]`, `rocket::ignite().launch()` | `socket()/bind()/listen()/accept()` + dispatch |
| `Ruma<T>` FromRequest guard (serde deserialization) | `ruma::Ruma<RegisterRequest>::from_body()` |
| `ruma_client_api::r0::account::register::{Request,Response}` | `ruma::RegisterRequest` / `ruma::RegisterResponse` structs |
| `body.device_id.clone().unwrap_or_default()` | `body.device_id.value_or("")` (`Option` → `std::optional`) |
| `"42".to_owned()` | `"42"` member init in the aggregate initializer |
| `UserId::try_into().unwrap()` | plain `std::string` (strong ID types arrive in a later step) |
| `pretty_env_logger::init()` | one `printf` banner at startup |

## Behavior

Identical to the original: any client that POSTs to
`/_matrix/client/r0/register` gets a hardcoded successful registration response.
Nothing is persisted; `access_token` is always `"42"`.

```console
$ curl -d '{"username":"neo","device_id":"DEVICE"}' http://127.0.0.1:8000/_matrix/client/r0/register
{"access_token":"42","device_id":"DEVICE","home_server":"deprecated","user_id":"@yourrequestedid:homeserver.com"}
```

## Build & run

```console
$ cmake -B build -S .
$ cmake --build build
$ ./build/conduit_step01

# or without cmake:
$ g++ -std=c++23 -Wall -Wextra main.cpp ruma_wrapper.cpp -o conduit_step01
```

## Why this matters for progressive-server

This stub already contains the skeleton every Matrix homeserver shares:

1. accept a client-server API HTTP request,
2. deserialize it into typed structures,
3. run handler logic (here: none),
4. serialize and return.

Later steps replace each piece with real machinery — persistence (RocksDB in
Conduit/tuwunel, SQLite/PostgreSQL here), auth tokens, room DAGs, federation —
but the request→type→handler→response shape never changes.
