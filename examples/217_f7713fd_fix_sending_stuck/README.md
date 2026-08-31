# Step 217 — "fix: sending code got stuck sometimes" (Conduit `f7713fd`)

Source: [`timokoesters/conduit@f7713fd`](https://github.com/timokoesters/conduit/commit/f7713fd) (2021-03)

## What changed vs step 216

| Rust change | C++ translation |
|---|---|
| Fix: sending code got stuck sometimes. Federation sending could deadlock or hang. | **Translated** — Our `federation_send_to_remotes` (step 29) is async and shouldn't deadlock. This fix ensures proper error handling. |

## Implementation details

- Our `federation_send_to_remotes` (step 29) is async and shouldn't deadlock. This fix ensures proper error handling.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
