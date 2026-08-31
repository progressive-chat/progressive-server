# Step 432 — "Return the ID of the appservice that was created by register_appservice" (Conduit `e24d75c`)

Source: [`timokoesters/conduit@e24d75c`](https://github.com/timokoesters/conduit/commit/e24d75c) (2022-02)

## What changed vs step 431

| Rust change | C++ translation |
|---|---|
| Return the ID of the appservice that was created by register_appservice. Duplicate of step 425. | **Translated** — Duplicate of step 425 — our appservice registration returns ID. |

## Implementation details

- Duplicate of step 425 — our appservice registration returns ID.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
