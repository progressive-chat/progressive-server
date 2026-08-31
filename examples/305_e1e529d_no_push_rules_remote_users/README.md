# Step 305 — "fix: don't apply push rules for users of other homeservers" (Conduit `e1e529d`)

Source: [`timokoesters/conduit@e1e529d`](https://github.com/timokoesters/conduit/commit/e1e529d) (2021-05)

## What changed vs step 304

| Rust change | C++ translation |
|---|---|
| Fix: don't apply push rules for users of other homeservers. Push rules only for local users. | **Translated** — Our push rules (steps 181-182, 186-187) apply to local users. This enforces the boundary. |

## Implementation details

- Our push rules (steps 181-182, 186-187) apply to local users. This enforces the boundary.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
