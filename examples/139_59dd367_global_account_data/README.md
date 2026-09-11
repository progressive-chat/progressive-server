# Step 139 — "fix: putting global account data works now" (Conduit `59dd367`)

Source: [`timokoesters/conduit@59dd367`](https://github.com/timokoesters/conduit/commit/59dd367) (2021-05-29)

Upstream adds an explicit `serde_json::Value` type annotation when parsing
account-data bodies (no behavior change).

## What changed vs step 138

**Nothing in `src/` — this directory was a byte-identical copy.** The commit
only pins a Rust type parameter; the port's `nlohmann::json::parse` needs no
such annotation.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit139 && ./build/tests
```
