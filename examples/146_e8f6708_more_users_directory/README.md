# Step 146 — "improvement: show more users in our user directory" (Conduit `e8f6708`)

Source: [`timokoesters/conduit@e8f6708`](https://github.com/timokoesters/conduit/commit/e8f6708) (2021-06-12)

Upstream stops filtering deactivated users out of user-directory search and
matches case-insensitively on user id and display name.

## What changed vs step 145

**Nothing in `src/` — this directory was a byte-identical copy.** The
modern chain's user-directory search already matches case-insensitively and
no longer filters out deactivated users, so the behavior is covered.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit146 && ./build/tests
```
