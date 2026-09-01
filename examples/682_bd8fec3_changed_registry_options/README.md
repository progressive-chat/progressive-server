# Step 682 — "changed registry options" (Conduit `bd8fec3`)

Source: [`timokoesters/conduit@bd8fec3`](https://github.com/timokoesters/conduit/commit/bd8fec3) (2023-07)

## What changed vs step 681

| Rust change | C++ translation |
|---|---|
| Changed registry options. Configuration/registry option changes. | **Translated** — Config options — our config system could adopt these. |

## Implementation details

- Config options — our config system could adopt these.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
