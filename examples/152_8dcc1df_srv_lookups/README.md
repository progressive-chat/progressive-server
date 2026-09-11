# Step 152 — "improvement: always use port from SRV lookups" (Conduit `8dcc1df`)

Source: [`timokoesters/conduit@8dcc1df`](https://github.com/timokoesters/conduit/commit/8dcc1df) (2020-12-08)

Upstream reworks federation destination resolution and, as the fix for #29,
also queries SRV records when no `.well-known` file is found.

This directory used to be a byte-identical copy of the attempt-A base; it is
rebuilt on the previous real step (151) and now really implements the
portable part.

## What changed vs step 151

| Rust change | C++ translation |
|---|---|
| **Query SRV when `.well-known` is missing (fixes #29)** | **Implemented** — `find_actual_destination` falls through to `lookup_srv_record(destination)` when there is no `.well-known`; the Host header keeps the original name, exactly like upstream |
| **Always use the port from SRV lookups** | **Already covered** — the SRV-hit branches (both the old `.well-known` one and the new fallback) carry the looked-up port |
| **`get_ip_with_port` / `add_port_to_hostname` / typed destinations** | **Already covered** — branches 1, 2, 3.x predate this commit in both codebases |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit152srv
```
