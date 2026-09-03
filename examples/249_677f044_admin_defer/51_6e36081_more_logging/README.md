# Step 51 — "improvement: more logging" (Conduit `6e36081`)

Source: [`timokoesters/conduit@6e36081`](https://github.com/timokoesters/conduit/commit/6e36081) (2020-11-15)

## What changed vs step 50

| Rust change | C++ translation |
|---|---|
| **Added `info!` logging for user registration** | **Translated** — Added `LOG_INFO` for user registration |
| **Added `info!` logging for account deactivation** | **Translated** — Added `LOG_INFO` for account deactivation |
| **Added `info!` logging for room visibility changes** | **Translated** — Added `LOG_INFO` for room visibility changes |
| **Added `info!` logging for room creation** | **Translated** — Added `LOG_INFO` for room creation |
| **Added `info!` logging for user login** | **Translated** — Added `LOG_INFO` for user login |
| **Fixed database error message formatting** | **Translated** — Fixed error message formatting |
| **Fixed DNS resolver error handling** | **Translated** — Fixed DNS resolver error handling |

## Implementation details

1. **Added logging for user registration** in `register_route`
2. **Added logging for account deactivation** in `deactivate_route`
3. **Added logging for room visibility changes** in `set_room_visibility_route`
4. **Added logging for room creation** in `create_room_route`
5. **Added logging for user login** in `login_route`
6. **Fixed database error message formatting** in `Database::try_remove`
6. **Fixed DNS resolver error handling** in `send_request`

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
