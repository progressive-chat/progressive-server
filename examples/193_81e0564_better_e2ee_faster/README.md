# Step 193 — "improvement: better e2ee over fed, faster incoming event handling" (Conduit `81e0564`)

Source: [`timokoesters/conduit@81e0564`](https://github.com/timokoesters/conduit/commit/81e0564) (2021-08-24)

## What changed vs step 192

| Rust change | C++ translation |
|---|---|
| **Better e2ee over federation** | **Translated** — Better e2ee over fed |
| **Faster incoming event handling** | **Translated** — Faster incoming events |
| **Major server_server refactor** | **Translated** — Cleaner server_server |
| **Major rooms.rs refactor** | **Translated** — Cleaner rooms code |

## Implementation details

1. **Better e2ee over fed** — Better e2ee over federation
2. **Faster incoming events** — Faster incoming event handling
3. **Major server_server refactor** — Major refactor of server_server
4. **Major rooms refactor** — Major refactor of rooms.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
