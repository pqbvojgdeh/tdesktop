# ClientHello profile maintenance

The browser labels in these patches describe captured wire profiles, not a
promise that the bytes remain representative forever. Review them before the
deadline in `clienthello-profile-review.json`; the validation workflow fails
after that date until the deadline and review record are updated.

## Required review evidence

For every retained profile, capture a fresh ClientHello from the named browser
on its native platform and record:

- browser version, operating system, capture date, target endpoint and whether
  the hello is fresh or resumed;
- SHA-256 of the sanitized packet capture or exact ClientHello byte dump;
- TLS record and handshake lengths, cipher suites, extension IDs and observed
  extension-order randomization;
- supported groups, key shares, signature algorithms, ALPN, GREASE positions,
  ECH/ALPS/SCT/session-ticket presence and PSK placement;
- JA3 and JA4 before and after the patch update.

Update the profile label, encoded blocks and both fresh/resumed validator
expectations together. Do not infer future browser bytes from draft standards
or version numbers alone.

## Current open evidence gaps

- Chromium 150 signature algorithms `0x0904`, `0x0905` and `0x0906` still need
  confirmation from a real Chrome 150 capture. The same capture must confirm
  extensions `0x0012` (SCT) and `0x0023` (session_ticket).
- Chromium synthetic resumption uses a fixed 113-byte identity and does not
  possess a ticket issued by the observed server. A stateful observer can
  distinguish this from real TLS resumption. Do not randomize the identity
  length without server-specific capture evidence.
- YandexGost is intentionally emitted as a fresh ClientHello. Its previous
  unconditional PSK made even the first connection look resumed.

## Selection policy

`RANDOM` means one process-session choice, reused by all simultaneous
connections. Safari is eligible only on macOS. YandexGost is eligible only
when the system locale is Russian. Explicit user selection remains available
for diagnostic use and is not filtered.
