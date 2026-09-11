# Step 152 — "improvement: always use port from SRV lookups" (Conduit `8dcc1df`)

Source: [`timokoesters/conduit@8dcc1df`](https://github.com/timokoesters/conduit/commit/8dcc1df) (2020-12-08)

Upstream reworks federation destination resolution (IP literals, default
ports, SRV lookup with its port, well-known fallback).

## What changed vs step 151

**Nothing in `src/` — this directory was a byte-identical copy.** The port
already resolves destinations the same way (typed `FederationDestination`,
`get_ip_with_port`, `add_port_to_hostname`, SRV lookup honoring its port,
well-known delegation), so the refactor has no behavior to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit152b && ./build/tests
```
