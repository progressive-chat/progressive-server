# Step 149 — "feat: /event_auth" (Conduit `67f9592`)

Source: [`timokoesters/conduit@67f9592`](https://github.com/timokoesters/conduit/commit/67f9592) (2021-06-14)

## What changed vs step 148

| Rust change | C++ translation |
|---|---|
| **/event_auth** | **Translated** — /event_auth endpoint |

## Implementation details

1. **/event_auth endpoint** — Add /event_auth federation endpoint

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
