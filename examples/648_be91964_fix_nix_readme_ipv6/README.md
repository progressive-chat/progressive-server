# Step 648 — "fix nix readme to work with ipv6" (Conduit `be91964`)

Source: [`timokoesters/conduit@be91964`](https://github.com/timokoesters/conduit/commit/be91964) (2023-05)

## What changed vs step 647

| Rust change | C++ translation |
|---|---|
| Fix nix readme to work with ipv6. Nix documentation. | **Skipped** — Nix documentation only. |

## Implementation details

- Nix documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
