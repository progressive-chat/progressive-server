# Step 182 — "feature: push rule settings" (Conduit `265fab8`)

Source: [`timokoesters/conduit@265fab8`](https://github.com/timokoesters/conduit/commit/265fab8) (2021-01)

## What changed vs step 181

| Rust change | C++ translation |
|---|---|
| Feature: push rule settings (continuation). More push rule settings and API. | **Translated** — Continuation of step 181. |

## Implementation details

- Continuation of step 181.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
