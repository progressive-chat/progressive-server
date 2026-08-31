# Step 350 — "Implement From<AnyInitialStateEvent> on PduBuilder" (Conduit `666e1d3`)

Source: [`timokoesters/conduit@666e1d3`](https://github.com/timokoesters/conduit/commit/666e1d3) (2021-07)

## What changed vs step 349

| Rust change | C++ translation |
|---|---|
| Implement From<AnyInitialStateEvent> on PduBuilder. Rust trait implementation for event building. | **No-op for us** — Rust trait — our C++ builds events directly. |

## Implementation details

- Rust trait — our C++ builds events directly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
