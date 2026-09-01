# Step 674 — "fix: actually clear memory in the admin commands" (Conduit `edd4a37`)

Source: [`timokoesters/conduit@edd4a37`](https://github.com/timokoesters/conduit/commit/edd4a37) (2023-07)

## What changed vs step 673

| Rust change | C++ translation |
|---|---|
| Fix: actually clear memory in the admin commands. Admin memory clearing command. 1 file changed. | **Translated** — Matches steps 375-378, 669 — admin memory commands. This clears memory. |

## Implementation details

- Matches steps 375-378, 669 — admin memory commands. This clears memory.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
