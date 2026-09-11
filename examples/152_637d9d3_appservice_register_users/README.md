# Step 152 — "Always allow appservices to register new users" (Conduit `637d9d3`)

Source: [`timokoesters/conduit@637d9d3`](https://github.com/timokoesters/conduit/commit/637d9d3) (2021-06-19)

Upstream lets appservices register users even when public registration is
disabled (`allow_registration` gate + `from_appservice` bypass).

This directory used to be a byte-identical copy of the attempt-A base; it is
rebuilt on the previous real step (151) and now really implements the
portable part.

## What changed vs step 151

| Rust change | C++ translation |
|---|---|
| **`allow_registration` gate on register** | **Implemented** — new `--allow-registration <bool>` / `--no-allow-registration` flag and `CONDUIT_ALLOW_REGISTRATION` env (default true, preserving current behavior since this port has no TOML layer) |
| **`from_appservice` bypass via appservice token** | **Implemented** — new `AppserviceManager::find_by_as_token()`; a `/register` request bearing a registered `as_token` skips the gate with 403 `M_FORBIDDEN` for everyone else when closed |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
# open registry (default): dummy-auth register works
$ ./build/server --port 8000 --data-dir /tmp/conduit152a
# closed registry: plain register -> 403, appservice-token register -> 401 flows
$ ./build/server --no-allow-registration --port 8001 --data-dir /tmp/conduit152b
```
