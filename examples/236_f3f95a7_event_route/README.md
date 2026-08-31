# Step 236 — "improvement: /event route" (Conduit `f3f95a7`)

Source: [`timokoesters/conduit@f3f95a7`](https://github.com/timokoesters/conduit/commit/f3f95a7) (2021-04)

## What changed vs step 235

| Rust change | C++ translation |
|---|---|
| Improvement: `/event` route. Endpoint to fetch a single event by ID. Useful for clients and federation. | **Translated** — We don't have `/event/{eventId}` yet. This adds the event lookup API. |

## Implementation details

- We don't have `/event/{eventId}` yet. This adds the event lookup API.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
