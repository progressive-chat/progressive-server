# Step 1 — Conduit's initial commit, translated to C++

Source: [`timokoesters/conduit@6264628c`](https://github.com/timokoesters/conduit/commit/6264628c113188af3a69ec16dcc4401884d95868)
— "Initial commit", 2020-02-15. Commit zero of the entire Rust line of Matrix
homeservers (Conduit → conduwuit → tuwunel / continuwuity).

The original was a Rocket app with a single stub endpoint. This translation is
a full C++ project using the real equivalents: **cpp-httplib** for Rocket,
**nlohmann/json** for serde_json.

## Files

| Conduit (Rust) | Here | Role |
|---|---|---|
| `Cargo.toml` | `CMakeLists.txt` | deps: httplib + nlohmann_json |
| `src/main.rs` | `src/main.cpp` | route handler + server launch |
| `src/ruma_wrapper.rs` | `src/ruma_wrapper.{hpp,cpp}` | `Ruma<T>` extractor, `MatrixResult<T>` responder, types |

## Concept map

| Rust | C++ |
|---|---|
| `#[post("/_matrix/client/r0/register")]` | `svr.Post(...)` |
| `rocket::ignite().mount(routes![]).launch()` | `svr.listen(...)` |
| `Ruma<T>` FromData guard | `ruma::Ruma<RegisterRequest>::from_request(req)` |
| `body.device_id.clone().unwrap_or_default()` | `body.device_id.value_or("")` |
| `"42".to_owned()` | `"42"` in aggregate init |

## Behavior — identical to the original

```console
$ curl -d '{"username":"neo","device_id":"DEVICE"}' http://127.0.0.1:8000/_matrix/client/r0/register
{"access_token":"42","device_id":"DEVICE","home_server":"deprecated","user_id":"@yourrequestedid:homeserver.com"}
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server
```
