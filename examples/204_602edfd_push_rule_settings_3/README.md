# Step 204 — "feature: push rule settings" (Conduit `602edfd`)

Source: [`timokoesters/conduit@602edfd`](https://github.com/timokoesters/conduit/commit/602edfd) (2021-02)

## What changed vs step 203

| Rust change | C++ translation |
|---|---|
| Feature: push rule settings (continuation). More push rule settings API. | **Translated** — Continuation of steps 181-182 (push rule settings). |

## Implementation details

- Continuation of steps 181-182 (push rule settings).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
