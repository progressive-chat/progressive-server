# Step 205 — "Resolved state is set as the current room state on incoming events" (Conduit `68f6093`)

Source: [`timokoesters/conduit@68f6093`](https://github.com/timokoesters/conduit/commit/68f6093) (2021-02)

## What changed vs step 204

| Rust change | C++ translation |
|---|---|
| Resolved state is set as the current room state on incoming events. Duplicate of step 183 (894b6ef). | **Translated** — Our state-res (step 83) does this. |

## Implementation details

- Our state-res (step 83) does this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
