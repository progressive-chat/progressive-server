# Step 67 — "Sort and authenticate the events from /send_join response" (Conduit `2a63d09`)

Source: [`timokoesters/conduit@2a63d09`](https://github.com/timokoesters/conduit/commit/2a63d09) (2020-08)

## What changed vs step 66

| Rust change | C++ translation |
|---|---|
| Sorts and authenticates the events from the `/send_join` federation response. This is critical for state resolution after join. | **Partial** — our `send_join` handler (step 29) doesn't do the full sort+auth. Would need state-res integration. |

## Implementation details

- **Partial** — our `send_join` handler (step 29) doesn't do the full sort+auth. Would need state-res integration.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
