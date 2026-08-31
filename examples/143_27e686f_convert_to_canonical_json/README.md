# Step 143 — "Convert uses of serde_json::Value to CanonicalJsonObject" (Conduit `27e686f`)

Source: [`timokoesters/conduit@27e686f`](https://github.com/timokoesters/conduit/commit/27e686f) (2020-12)

## What changed vs step 142

| Rust change | C++ translation |
|---|---|
| Convert uses of `serde_json::Value` to `CanonicalJsonObject` throughout the federation code. Canonical JSON is a strict subset of JSON that ensures consistent hashing. | **Translated** — Our JSON serialization uses nlohmann/json with sorted keys (deterministic). The `crypto::sign_json` uses canonical JSON for signature computation. |

## Implementation details

- Our JSON serialization uses nlohmann/json with sorted keys (deterministic). The `crypto::sign_json` uses canonical JSON for signature computation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
