# Step 321 — "Fix docs for fetch_and_handle_events" (Conduit `1bb84a8`)

Source: [`timokoesters/conduit@1bb84a8`](https://github.com/timokoesters/conduit/commit/1bb84a8) (2021-06)

## What changed vs step 320

| Rust change | C++ translation |
|---|---|
| Fix docs for fetch_and_handle_events. Documentation fix for event handling. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
