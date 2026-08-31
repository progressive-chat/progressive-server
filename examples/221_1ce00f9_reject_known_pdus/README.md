# Step 221 — "fix: don't accept incoming pdus if we know about them already" (Conduit `1ce00f9`)

Source: [`timokoesters/conduit@1ce00f9`](https://github.com/timokoesters/conduit/commit/1ce00f9) (2021-03)

## What changed vs step 220

| Rust change | C++ translation |
|---|---|
| Fix: don't accept incoming pdus if we know about them already. Early deduplication in the incoming PDU handler. | **Translated** — Our step 210 (591769d) already filters PDUs before the main loop. This is the same fix. |

## Implementation details

- Our step 210 (591769d) already filters PDUs before the main loop. This is the same fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
