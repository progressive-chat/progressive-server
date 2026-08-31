# Step 457 — "fix: do not panic on a JSON not containing the PDU" (Conduit `d421700`)

Source: [`timokoesters/conduit@d421700`](https://github.com/timokoesters/conduit/commit/d421700) (2022-02)

## What changed vs step 456

| Rust change | C++ translation |
|---|---|
| Fix: do not panic on a JSON not containing the PDU. Handle missing PDU in JSON gracefully. | **Translated** — Our JSON parsing (nlohmann/json) handles missing fields. This fixes a Rust panic. |

## Implementation details

- Our JSON parsing (nlohmann/json) handles missing fields. This fixes a Rust panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
