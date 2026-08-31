# Step 240 — "fix: malformed pushrule error when event does not trigger any actions" (Conduit `b0ea692`)

Source: [`timokoesters/conduit@b0ea692`](https://github.com/timokoesters/conduit/commit/b0ea692) (2021-04)

## What changed vs step 239

| Rust change | C++ translation |
|---|---|
| Fix: malformed pushrule error when event does not trigger any actions. Better error handling for push rules. | **Translated** — Our push rules (steps 181-182, 186-187) handle this case. This fixes the Rust version. |

## Implementation details

- Our push rules (steps 181-182, 186-187) handle this case. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
