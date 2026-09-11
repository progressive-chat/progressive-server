# Step 140 — "fix: deactivate accounts that should be deactivated" (Conduit `88cf043`)

Source: [`timokoesters/conduit@88cf043`](https://github.com/timokoesters/conduit/commit/88cf043) (2021-05-30)

Upstream switches password handling to `Option` so deactivated accounts
(those without a password) are properly deactivated, and tweaks the media
`Content-Disposition` filename.

## What changed vs step 139

**Nothing in `src/` — this directory was a byte-identical copy.** This port
marks deactivated accounts with an empty password string (upstream
convention since step 23) and its account-deactivation flow already removes
devices and blanks the password, so the `Option` refactor has no behavior
to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit140 && ./build/tests
```
