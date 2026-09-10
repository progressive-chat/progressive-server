# Step 809 — "add support for arbitrary proxies" (Conduit `b2d55160`)

Source: [`timokoesters/conduit@b2d55160`](https://github.com/timokoesters/conduit/commit/b2d55160) (2021-04-13, merged 2021-07-01)

Folds in `f25f61d4` (rebase fixup, drops a stray `#[derive(Clone)]`) and
`c53cc03f` ("address pr comments": moves the proxy types into their own
`src/database/proxy.rs` module + documents `proxy = "none"` in
`conduit-example.toml`). Skips `1bb84a8e` (comment-only docs fix for
`fetch_and_handle_events`) and `c30cc50a` (Cargo-only ruma bump) per the
project's skipped-commit rules.

## What changed vs step 808

| Rust change | C++ translation |
|---|---|
| **`ProxyConfig` enum (`None` / `Global { url }` / `ByDomain`) on `Config`** | **Implemented** — new `src/proxy.{hpp,cpp}` module (`proxy::ProxyConfig`, default `None`), held on `Data` via `set_proxy_config()` / `proxy_config()` |
| **`PartialProxyConfig::for_url` include/exclude matching** | **Implemented verbatim** — most-specific-include must beat most-specific-exclude, empty include list means `*` |
| **`WildCardedDomain` (`*`, `*.suffix`, exact)** | **Implemented verbatim** — `parse` / `matches` (suffix `ends_with`, leading-dot form) / `more_specific_than` |
| **`deserialize_from_str` helper** | **Folded into the module** — `ProxyUrl::parse` / `WildCardedDomain::parse` (no serde layer in this port) |
| **reqwest `socks` feature + proxy on the federation client** | **Implemented as HTTP proxy** — `apply_proxy()` calls `httplib::Client::set_proxy(host, port)` on the federation `SSLClient` (`send_request`), the `.well-known` fetch, and the signing-key live fetch when the rules match the destination |
| **`proxy.rs` module split + `proxy = "none"` example config** | **Implemented** — proxy lives in its own `src/proxy.*` unit; no TOML layer exists in this port, so the same shapes are accepted via `--proxy <spec>` / `CONDUIT_PROXY` (`"none"`, a bare URL, or JSON `{"global":...}` / `{"by_domain":[...]}`) |

Transport note: upstream enables reqwest's `socks` support, so
`socks5://` URLs work there. cpp-httplib only speaks HTTP proxies, so a
configured endpoint is applied as `host:port` regardless of scheme. Domain
matching semantics are identical.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit130
$ CONDUIT_PROXY=none ./build/server --port 8001 --data-dir /tmp/conduit130b
$ ./build/server --proxy http://127.0.0.1:8080 --port 8002 --data-dir /tmp/conduit130c
```
