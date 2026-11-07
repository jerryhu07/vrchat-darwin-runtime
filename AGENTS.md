# Runtime source preview

- Keep VRChat and EAC files intact. Preserve the exact validated local runtime and its separate prefix.
- Wine owns Windows semantics, FEX owns CPU translation, DXMT owns graphics, and the startup executor supplies the required Linux ABI. Prefer those existing mechanisms.
- Use the pinned source fetch/build commands and owned fixtures. Keep source build results separate from online game verification.
- Keep proprietary binaries, credentials, Wine prefixes, raw logs, private paths and build products out of Git and source packages.
- Preserve provenance and license notices. Keep patches focused and record validation at the layer actually exercised.
