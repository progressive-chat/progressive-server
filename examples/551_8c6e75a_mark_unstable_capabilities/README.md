# Step 551 — "Mark unstable versions as unstable in /capabilities" (Conduit `8c6e75a`)

Source: [`timokoesters/conduit@8c6e75a`](https://github.com/timokoesters/conduit/commit/8c6e75a) (2022-10)

## What changed vs step 550

| Rust change | C++ translation |
|---|---|
| Mark unstable versions as unstable in /capabilities. Capability version reporting. | **Translated** — Our /capabilities (step 8) reports versions. This marks unstable ones. |

## Implementation details

- Our /capabilities (step 8) reports versions. This marks unstable ones.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
