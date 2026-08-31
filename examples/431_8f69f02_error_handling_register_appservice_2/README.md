# Step 431 — "add error handling for register_appservice too" (Conduit `8f69f02`)

Source: [`timokoesters/conduit@8f69f02`](https://github.com/timokoesters/conduit/commit/8f69f02) (2022-02)

## What changed vs step 430

| Rust change | C++ translation |
|---|---|
| Add error handling for register_appservice too. Duplicate of step 424. | **Translated** — Duplicate of step 424 — our appservice registration handles errors. |

## Implementation details

- Duplicate of step 424 — our appservice registration handles errors.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
