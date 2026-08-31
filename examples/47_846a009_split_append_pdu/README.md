# Step 47 — "Split append_pdu -> append_pdu and build_and_append" (Conduit `846a0098`)

Source: [`timokoesters/conduit@846a0098`](https://github.com/timokoesters/conduit/commit/846a0098) (2020-08)

## What changed vs step 46

| Rust change | C++ translation |
|---|---|
| Splits `append_pdu` into `build_and_append_pdu` (the existing build+store flow) and `append_pdu` (just store a pre-built PDU). Adds `append_state_pdu` for state events that also compute the StateHash. | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
