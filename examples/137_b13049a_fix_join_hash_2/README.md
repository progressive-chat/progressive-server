# Step 137 — "Fix federated join miss hashing the join event created" (Conduit `b13049a`)

Source: [`timokoesters/conduit@b13049a`](https://github.com/timokoesters/conduit/commit/b13049a) (2020-12)

## What changed vs step 136

| Rust change | C++ translation |
|---|---|
| Same fix as 136 — duplicate commit that does the same fix in a different file path. | **Translated** — Our `crypto::reference_hash` covers this. |

## Implementation details

- Our `crypto::reference_hash` covers this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
