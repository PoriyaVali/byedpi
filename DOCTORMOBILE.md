# Mirage — Doctor Mobile's DPI-evasion core (fork of byedpi)

This is **Doctor Mobile's owned fork** of [hufrea/byedpi](https://github.com/hufrea/byedpi)
(MIT). byedpi is a local SOCKS proxy that defeats SNI-based DPI censorship in
**userspace, with no root**, by desynchronising the DPI from the real server
(split / disorder / fake-packet + TTL / TLS-record fragmentation). We ship it as
one of the app's anti-censorship engines (`libbyedpi.so`), and build it
ourselves for every platform so we can inject the same core anywhere: the
Android app, a Windows/desktop edition, and OpenWRT routers.

## Why we forked it
We own our whole stack (sing-box, mihomo, mdns, Xray, V2bX, panel). This is the
DPI-evasion piece — owned, built by our CI, reproducible.

## Measured winning preset for Iran (2026-08-05, real Irancell, rooted device)
On residential Irancell, **plain TLS-record fragmentation alone is NOT enough**
(the DPI reassembles / is stricter than datacenter paths). The combination that
loaded real Instagram + YouTube (http 200) end-to-end, past DNS-poisoning +
SNI-DPI + blocked DoH, was:

```
--fake 1+s --ttl 6 --tlsrec 1+s
```

Also strong: `--oob 1+s --disorder 1+s`, and byedpi's native **auto** mode
(`-A torst,ssl_err ...`) which detects a reset and rotates desync params,
caching the working one per destination IP — a self-tuning default.

## Mirage-shaped ClientHellos (17.3-dm3)
Our sing-box and mihomo can cut the ClientHello into TLS records themselves
("Mirage": a 10-byte first record ending before the SNI, then the rest, each in
its own write - measured to pass Hamrah-e Aval, which drops the single-write
form). byedpi sits after them when both are on, and it used to break that:

- `parse_tls` only finds the SNI inside one record, so on a split hello every
  `+s` position resolved to nothing and the desync groups sent the records
  unchanged, **in one write** - no desync, and the shape MCI drops.
- A plain group forwarded whatever one read returned, so both records left in
  one write whenever they were read together (timing-dependent).

Now (desync.c `chello_records` / `merge_chello`): a group that changes the
hello merges the records back into one first, so its SNI positions and
`--tlsrec` work; a plain group forwards the records one write each. Captured on
loopback with the real mihomo core and this build: first try `10 + 1516`
(Mirage kept), retry `118 + 2 + 1401` (merged, split at the SNI); before, both
were a single 1526-byte segment. Real TLS 1.3 handshakes completed through
split, tlsrec, split+disorder and plain, with Mirage in both write modes. A
hello that is not split into records is handled exactly as before.

Trade-off: through byedpi a split hello always leaves one record per write, so
the cores' `DM_MIRAGE_COALESCE=1` (single-write form) has no effect here - byedpi
cannot tell one client write from two that it read together.

## Build
Pure C, `make`.
- Linux / Android / router: `make CC=<target-gcc-or-ndk-clang>`
- Windows: `make windows CC=x86_64-w64-mingw32-gcc`
- Android per-ABI: `make CC="<ndk>/clang --target=aarch64-linux-android24"` then
  rename `ciadpi` → `libbyedpi.so`.

## CI
- `.github/workflows/android-dm.yml` → `libbyedpi-<abi>.so` (arm64-v8a, armeabi-v7a, x86_64)
- `.github/workflows/desktop-wrt-dm.yml` → `mirage-<os>-<arch>[.exe]` (linux amd64/arm64/armv7/mipsle/mips, windows amd64)

Both trigger on a `v*-dm*` tag and publish to that tag's Release.

Upstream: https://github.com/hufrea/byedpi — license MIT (see `LICENSE`).
