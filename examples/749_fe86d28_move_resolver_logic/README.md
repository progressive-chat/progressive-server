# Step 749 — "move resolver logic into the resolver" (Conduit `fe86d28`)

Source: [`timokoesters/conduit@fe86d28`](https://github.com/timokoesters/conduit/commit/fe86d28) (2024-01)

## What changed vs step 748

| Rust change | C++ translation |
|---|---|
| Move resolver logic into the resolver. DNS resolver code organization. 1 file changed. | **Translated** — Our resolver (step 96, 214) is organized. This reorganizes Rust code. |

## Implementation details

- Our resolver (step 96, 214) is organized. This reorganizes Rust code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
