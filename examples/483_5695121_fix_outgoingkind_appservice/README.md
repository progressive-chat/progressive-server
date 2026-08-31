# Step 483 — "Fix wrong associated type in OutgoingKind::Appservice" (Conduit `5695121`)

Source: [`timokoesters/conduit@5695121`](https://github.com/timokoesters/conduit/commit/5695121) (2022-03)

## What changed vs step 482

| Rust change | C++ translation |
|---|---|
| Fix wrong associated type in OutgoingKind::Appservice. Type fix for appservice outgoing events. | **Translated** — Our appservice (step 96) handles outgoing correctly. This fixes a Rust type issue. |

## Implementation details

- Our appservice (step 96) handles outgoing correctly. This fixes a Rust type issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
