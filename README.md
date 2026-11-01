<!-- SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht -->
<!-- SPDX-License-Identifier: MIT -->

# bundle-provenance

[![CI](https://github.com/koodikiht/bundle-provenance/actions/workflows/ci.yml/badge.svg)](https://github.com/koodikiht/bundle-provenance/actions/workflows/ci.yml) [![SLSA Build Level 3](https://img.shields.io/badge/SLSA-Build%20Level%203-brightgreen)](https://github.com/koodikiht/bundle-provenance/attestations) [![REUSE status](https://api.reuse.software/badge/github.com/koodikiht/bundle-provenance)](https://api.reuse.software/info/github.com/koodikiht/bundle-provenance) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Post-build supply-chain and binary hardening inspector for packaged client artifacts (`Electron`, `Mach-O`, `ASAR`, and `SourceMap v3` web bundles).

Lockfile scanners see what was declared before compilation. Packaging hooks (`electron-builder`, `afterPack`, bundler plugins) strip binary hardening flags, ship unhashed `app.asar` archives, or pull undeclared packages into the final bundle. `bundle-provenance` parses the compiled output in memory without extracting untrusted archives to disk. It recovers `Package-URL` (`purl`) coordinates and writes `CycloneDX v1.6` or `SARIF v2.1.0` reports.

## Usage

Requires `bun >= 1.1` (or `node >= 22.6` with `--experimental-strip-types`). Zero runtime npm dependencies.

```bash
# Scan an Electron executable
bun run src/cli.ts scan /Applications/App.app/Contents/MacOS/App --fail-on-high

# Dump a CycloneDX 1.6 SBOM from app.asar without unpacking to disk
bun run src/cli.ts scan /Applications/App.app/Contents/Resources/app.asar --format cyclonedx > sbom.cdx.json

# Diff a minified JS bundle against package.json
bun run src/cli.ts scan dist/app.min.js --map dist/app.min.js.map --manifest package.json --format sarif

# Run unit tests
bun test
```

## Checks

- `FUSE-001..006` (`src/fuses.ts`): locates the 32-byte Electron Fuse v1 sentinel (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`) in raw ELF/Mach-O/PE binaries, decodes the 8-byte fuse vector (`RunAsNode`, `EnableCookieEncryption`, `EnableNodeOptionsEnvironmentVariable`, `EnableNodeCliInspectArguments`, `EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`), and prints exact hex offsets.
- `MACHO-001..005` (`src/macho.ts`): parses embedded `CSMAGIC_EMBEDDED_ENTITLEMENTS` (`0xfade7171`) XML plist blobs. Cross-checks `cs.allow-dyld-environment-variables`, `cs.disable-library-validation`, `cs.debugger`, and `get-task-allow` against macOS TCC grants and fuse states.
- `ASAR-001..003` (`src/asar.ts`): reads the 16-byte little-endian `UInt32` Chromium Pickle header in memory. Flags `..` path traversal entries, checks 4MB block integrity hashes, hashes nested `node_modules/**/package.json` manifests into `pkg:npm/...` PURLs, and lists native `.node` / `.dylib` / `.so` / `.dll` addons.
- `BUNDLE-001` (`src/sourcemap.ts`): reconstructs package versions from `SourceMap v3` `sources` paths (including `.pnpm` virtual stores) and `@license` banners. Flags phantom packages missing from `--manifest` and extracts hardcoded `https://` and `wss://` endpoints.

## Output formats

- `--format text`: terminal report with byte offsets and severity counts.
- `--format json`: structured PURL inventory and findings for AboutCode `PurlDB` ingestion.
- `--format cyclonedx`: `CycloneDX v1.6` JSON SBOM.
- `--format sarif`: `SARIF v2.1.0` for GitHub Code Scanning and CI gates (`--fail-on-high`).

## Bugs found in the wild

| Target | Finding | Issue |
| :--- | :--- | :--- |
| DeltaChat Desktop (`v2.65.0` arm64) | `FUSE-004` / `FUSE-005` (`ASAR-002`): `afterPackHook.mjs` disables `runAsNode` and `enableNodeCliInspectArguments`, but leaves `EnableEmbeddedAsarIntegrityValidation` (`0x30`) and `OnlyLoadAppFromAsar` (`0x30`) off at Mach-O offset `0x0934fd38`. | [`#6914`](https://github.com/deltachat/deltachat-desktop/issues/6914) |
| Ferdium Desktop (`v7.2.3` arm64) | `FUSE-001..003`: `electron-builder.yml` enables ASAR integrity validation while leaving `RunAsNode` (`0x31`), `EnableNodeOptionsEnvironmentVariable` (`0x31`), and `EnableNodeCliInspectArguments` (`0x31`) enabled in `Ferdium.app`. | [`#2607`](https://github.com/ferdium/ferdium-app/issues/2607) |

## License

MIT © 2026 Mark ([@malfunctionAI](https://github.com/malfunctionAI)) / [KoodiKiht](https://koodikiht.dev). Compliant with [FSFE REUSE 3.2](https://reuse.software/).
