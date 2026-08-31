# Step 198 — "Abstract event validation/fetching, add outlier and signing key DB trees" (Conduit `4cf530c`)

Source: [`timokoesters/conduit@4cf530c`](https://github.com/timokoesters/conduit/commit/4cf530c) (2021-02)

## What changed vs step 197

| Rust change | C++ translation |
|---|---|
| Abstract event validation/fetching, add outlier and signing key DB trees. Duplicate of step 172 (851eb55). | **Translated** — Same as step 172 — our outlier + signing key DB in step 83. |

## Implementation details

- Same as step 172 — our outlier + signing key DB in step 83.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
