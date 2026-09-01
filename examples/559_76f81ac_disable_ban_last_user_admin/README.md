# Step 559 — "feat(db/rooms): disable banning for last user and conduit user in admins room" (Conduit `76f81ac`)

Source: [`timokoesters/conduit@76f81ac`](https://github.com/timokoesters/conduit/commit/76f81ac) (2022-10)

## What changed vs step 558

| Rust change | C++ translation |
|---|---|
| Feat(db/rooms): disable banning for last user and conduit user in admins room. Admin room ban protection. 1 file changed. | **Translated** — Matches steps 552-554 — admin room protections. This adds ban protection. |

## Implementation details

- Matches steps 552-554 — admin room protections. This adds ban protection.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
