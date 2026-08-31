# Step 283 — "feat: send read receipts over federation" (Conduit `8f27e61`)

Source: [`timokoesters/conduit@8f27e61`](https://github.com/timokoesters/conduit/commit/8f27e61) (2021-05)

## What changed vs step 282

| Rust change | C++ translation |
|---|---|
| Feat: send read receipts over federation. Read receipts (m.receipt) sent to remote servers. 6 files changed. MAJOR feature. | **Translated** — Our receipts (step 216 `dd68031_implement_receipt`) are local. This adds federation sending. |

## Implementation details

- Our receipts (step 216 `dd68031_implement_receipt`) are local. This adds federation sending.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
