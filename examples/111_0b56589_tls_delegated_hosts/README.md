# Step 111 — "feat: add handling of tls cert for delegated hosts" (Conduit `0b56589d`)

Source: [`timokoesters/conduit@0b56589d`](https://github.com/timokoesters/conduit/commit/0b56589d) (2021-04-15)

Folds in straight-order followers `b4c001de` (typed destination cleanup) and
`e73de231` (verify fallback for non-conformant servers).

## What changed vs step 110

| Rust change | C++ translation |
|---|---|
| **`FederationDestination` enum (`Literal`/`Named`) + `into_url`/`into_uri`/`host`** | **Implemented** — `federation::FederationDestination` in `server_server.hpp/.cpp` with the same constructors and methods |
| **Stringly resolution rewritten on the typed pair** | **Implemented** — `get_ip_with_port` / `add_port_to_hostname` / `find_actual_destination` / `query_srv_record` flow mirrors upstream steps 1–3 (IP literal, host+port, well-known → IP/port/SRV/plain) |
| **`tls_name_override` map populated on delegation** | **Implemented** — process-wide map (`note_tls_name_override`) filled when actual host ≠ delegated host |
| **`e73de231`: retry with original name + warn on verify failure** | **Adapted** — `tls_name_for()` prefers the override, falls back to the original name; verification itself stays disabled in the sandbox (proxy MITM), so the fallback is name selection + debug log |
| **rustls + native-certs client wiring** | **Documented** — C++ uses cpp-httplib/OpenSSL; no TLS-stack swap in this step |

## Behavioral notes

- Common cases resolve byte-identically to before (`host` → `host:8448`, `h:p` unchanged, delegation → `D:8448` + `Host: D`).
- One upstream-faithful difference: bare IP literals now yield `Host: ip:8448` instead of `Host: ip` (matches upstream `into_uri`; harmless with verification disabled).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
