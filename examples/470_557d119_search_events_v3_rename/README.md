# Step 470 — "change search_events_v3 to search_events::v3" (Conduit `557d119`)

Source: [`timokoesters/conduit@557d119`](https://github.com/timokoesters/conduit/commit/557d119) (2022-02)

## What changed vs step 469

| Rust change | C++ translation |
|---|---|
| Change search_events_v3 to search_events::v3. Module reorganization for search. 1 file changed. | **Translated** — Our /search (step 318) uses a different structure. This is a Rust module rename. |

## Implementation details

- Our /search (step 318) uses a different structure. This is a Rust module rename.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
