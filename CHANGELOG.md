## 0.3.0 (2026-05-31)

### Refactor

- drop OpenSSL-Package and COpenSSL; Ed448/X448 now use swift-goldilocks on all platforms (previously: OpenSSL on Apple+Linux, Goldilocks on Android+Wasi)
- downstream Mach-Os become fully static; the `@rpath/OpenSSL.framework` load command disappears
- Linux `libssl-dev` / `openssl-devel` build requirement removed

### Fix

- Ed448 public-key import error message previously said "Seed must be 56 bytes" while the guard required 57 — message corrected

### BREAKING CHANGE

- `Curve448Error.openSSLError` deprecated (kept for API compatibility, removal scheduled for next major)
- X448 `init(rawRepresentation:)` now validates seed length up front and throws `Curve448Error.incorrectKeySize` for non-56-byte input. Happy-path output is byte-equivalent (RFC 7748 / RFC 8032 are fully specified; existing RFC test vectors enforce this); error surface on bad input is stricter

## 0.2.3 (2026-05-29)

### Fix

- update packages

## 0.2.2 (2026-05-28)

### Refactor

- depend on swift-goldilocks instead of vendoring libgoldilocks

## 0.2.1 (2026-05-28)

### Fix

- drop unsafeFlags from CEd448Vendored so consumers can import

## 0.2.0 (2026-05-28)

### Feat

- vendor libgoldilocks for Android and Wasm Ed448/X448 support

## 0.1.4 (2026-05-11)

### Fix

- improve cross platform compatibility

## 0.1.3 (2025-11-29)

### Fix

- improve cross platform compatibility

## 0.1.2 (2025-08-24)

### Fix

- update CryptoSwift

## 0.1.1 (2025-08-09)

## 0.1.0 (2024-12-24)

### Feat

- add key pair generation methods
