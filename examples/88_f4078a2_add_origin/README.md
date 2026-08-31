# Step 88 — "fix: synapse complains about missing origin" (Conduit `f4078a2`)

Source: [`timokoesters/conduit@f4078a2`](https://github.com/timokoesters/conduit/commit/f4078a2) (2020-09)

## What changed vs step 87

| Rust change | C++ translation |
|---|---|
| Adds the `origin` field to outgoing federation PDUs (synapse complains if it's missing). | Our step 9 (`b0d9ccdb_signing`) already signs all outgoing events with the origin field. |

## Implementation details

- Our step 9 (`b0d9ccdb_signing`) already signs all outgoing events with the origin field.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
