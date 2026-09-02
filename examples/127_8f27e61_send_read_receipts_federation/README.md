# Step 127 — "feat: send read receipts over federation" (Conduit `8f27e61`)

Source: [`timokoesters/conduit@8f27e61`](https://github.com/timokoesters/conduit/commit/8f27e61) (2021-05-17)

## What changed vs step 126

| Rust change | C++ translation |
|---|---|
| **Send read receipts over federation** | **Translated** — Read receipts federation |
| **Major sending.rs refactor** | **Translated** — Cleaner sending code |

## Implementation details

1. **Read receipts over federation** — Send read receipts over federation (only if PDU is sent)
2. **Major sending refactor** — Major refactor of sending code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
