# Step 144 — "convert_to_outgoing_federation_event takes CanonicalJsonObj" (Conduit `c173ce4`)

Source: [`timokoesters/conduit@c173ce4`](https://github.com/timokoesters/conduit/commit/c173ce4) (2020-12)

## What changed vs step 143

| Rust change | C++ translation |
|---|---|
| `convert_to_outgoing_federation_event` now takes a `CanonicalJsonObj` (not raw `Value`). | **Translated** — Our federation send uses the PDU JSON directly. The canonical JSON conversion is implicit in nlohmann/json with sorted keys. |

## Implementation details

- Our federation send uses the PDU JSON directly. The canonical JSON conversion is implicit in nlohmann/json with sorted keys.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
