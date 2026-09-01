# Step 573 — "fix(client/login): username in lowercase for login by token" (Conduit `9a47069`)

Source: [`timokoesters/conduit@9a47069`](https://github.com/timokoesters/conduit/commit/9a47069) (2022-10)

## What changed vs step 572

| Rust change | C++ translation |
|---|---|
| Duplicate of step 549 (username lowercase for login by token). | **Skipped** — Duplicate of step 549. |

## Implementation details

- Duplicate of step 549.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
