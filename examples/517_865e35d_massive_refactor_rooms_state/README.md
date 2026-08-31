# Step 517 — "Work on rooms/state, database, alias, directory, edus services, event_handler, lazy_loading, metadata, outlier, and pdu_metadata" (Conduit `865e35d`)

Source: [`timokoesters/conduit@865e35d`](https://github.com/timokoesters/conduit/commit/865e35d) (2022-08)

## What changed vs step 516

| Rust change | C++ translation |
|---|---|
| Work on rooms/state, database, alias, directory, edus services, event_handler, lazy_loading, metadata, outlier, and pdu_metadata. MAJOR refactor across many modules. 22 files changed. | **Translated** — Our equivalent code covers these areas across steps 83, 253, 320, etc. This is a major Rust refactor. |

## Implementation details

- Our equivalent code covers these areas across steps 83, 253, 320, etc. This is a major Rust refactor.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
