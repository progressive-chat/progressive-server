# Step 59 — "fix: send notification count updates when private read receipts change" (Conduit `33215d6`)

Source: [`timokoesters/conduit@33215d6`](https://github.com/timokoesters/conduit/commit/33215d6) (2020-08)

## What changed vs step 58

| Rust change | C++ translation |
|---|---|
| Sends notification count updates when private read receipts change. Implements the `m.typing` / `m.receipt` EDU delivery to appservices. | **No-op for us** — we don't have appservice EDU delivery yet (deferred from step 96 work). |

## Implementation details

- **No-op for us** — we don't have appservice EDU delivery yet (deferred from step 96 work).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
