# Step 730 — "feat: send push notification on invite to invited user and etc" (Conduit `f3b6b3e`)

Source: [`timokoesters/conduit@f3b6b3e`](https://github.com/timokoesters/conduit/commit/f3b6b3e) (2023-11)

## What changed vs step 729

| Rust change | C++ translation |
|---|---|
| Feat: send push notification on invite to invited user and etc. Push notifications for invites. 1 file changed. | **Translated** — Our push notifications (steps 186-187) handle invites. This adds push on invite. |

## Implementation details

- Our push notifications (steps 186-187) handle invites. This adds push on invite.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
