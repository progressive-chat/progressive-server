# Step 615 — "build(nix): fix flake builds" (Conduit `5d913f7`)

Source: [`timokoesters/conduit@5d913f7`](https://github.com/timokoesters/conduit/commit/5d913f7) (2023-01)

## What changed vs step 614

| Rust change | C++ translation |
|---|---|
| Build(nix): fix flake builds. Nix build fix. | **No-op for us** — Nix build — our C++ uses CMake. |

## Implementation details

- Nix build — our C++ uses CMake.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
