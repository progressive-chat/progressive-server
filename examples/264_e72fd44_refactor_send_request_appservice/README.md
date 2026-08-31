# Step 264 — "Refactor send_request for appservices" (Conduit `e72fd44`)

Source: [`timokoesters/conduit@e72fd44`](https://github.com/timokoesters/conduit/commit/e72fd44) (2021-04)

## What changed vs step 263

| Rust change | C++ translation |
|---|---|
| Refactor send_request for appservices. Cleanup appservice request sending. | **Translated** — Our appservice send (step 96 `e08dfd9_srv_record`) is already clean. |

## Implementation details

- Our appservice send (step 96 `e08dfd9_srv_record`) is already clean.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
