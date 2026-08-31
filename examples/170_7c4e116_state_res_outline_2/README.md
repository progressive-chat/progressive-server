# Step 170 — "State resolution outline for /send" (Conduit `7c4e116`)

Source: [`timokoesters/conduit@7c4e116`](https://github.com/timokoesters/conduit/commit/7c4e116) (2021-01)

## What changed vs step 169

| Rust change | C++ translation |
|---|---|
| State resolution outline for `/send` (continuation of 163). | **Translated** — See step 163 — same work continued. |

## Implementation details

- See step 163 — same work continued.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
