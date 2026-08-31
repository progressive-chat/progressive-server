# Step 80 — "fix: filter public room dir" (Conduit `9f05ef9`)

Source: [`timokoesters/conduit@9f05ef9`](https://github.com/timokoesters/conduit/commit/9f05ef9) (2020-09)

## What changed vs step 79

| Rust change | C++ translation |
|---|---|
| Adds filtering to the public room directory by `generic_search_term` (case-insensitive match on room_id and room name). | Our step 34 (`9f05ef926_pubroom_filter`) implements the search filter. |

## Implementation details

- Our step 34 (`9f05ef926_pubroom_filter`) implements the search filter.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
