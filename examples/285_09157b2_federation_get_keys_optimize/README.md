# Step 285 — "improvement: federation get_keys and optimize signingkey storage" (Conduit `09157b2`)

Source: [`timokoesters/conduit@09157b2`](https://github.com/timokoesters/conduit/commit/09157b2) (2021-05)

## What changed vs step 284

| Rust change | C++ translation |
|---|---|
| Improvement: federation get_keys and optimize signingkey storage. Better key fetching and storage. 18 files changed. MAJOR. | **Translated** — Our key fetching (step 8, 214) and signing key storage (step 83) cover this. This optimizes them. |

## Implementation details

- Our key fetching (step 8, 214) and signing key storage (step 83) cover this. This optimizes them.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
