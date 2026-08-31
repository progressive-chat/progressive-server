# Step 188 — "Sync are-we-synapse with dendrite" (Conduit `1d7207b`)

Source: [`timokoesters/conduit@1d7207b`](https://github.com/timokoesters/conduit/commit/1d7207b) (2021-02)

## What changed vs step 187

| Rust change | C++ translation |
|---|---|
| Sync are-we-synapse with dendrite. Compatibility test updates. | **No-op for us** — Test suite compatibility — no production code change. |

## Implementation details

- Test suite compatibility — no production code change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
