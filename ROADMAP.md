<!-- SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht -->
<!-- SPDX-License-Identifier: MIT -->

# Technical roadmap (`v0.1.0 -> v1.0.0`)

`bundle-provenance` bridges the metadata gap between source-level SBOM scanners (`ScanCode`, `cdxgen`, `Syft`) and compiled client-side release artifacts where module boundaries and `Package-URL (purl)` coordinates are stripped during bundling.

## Completed baseline (`v0.1.0` - October 2026)

- Independent in-memory `Chromium Pickle` (`ASAR`) header parser with `SHA-256` manifest hashing and native addon detection (`.node`, `.dylib`, `.dll`, `.so`).
- Byte-level `Electron Fuses v1` wire sentinel scanner (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`) and security rule engine (`FUSE-001..006`).
- `SourceMap v3` and license-banner package lineage extractor with phantom (undeclared) dependency detection (`BUNDLE-001`).
- Standard `CycloneDX v1.6 JSON` and `SARIF v2.1.0` exporters.

---

## Planned milestones (aligned with CodeSupply / Open Internet Stack)

### Milestone 1 (`v0.3.0`): sourcemap-less bundler reconstruction and CRX3 extension verifier

- **Webpack / Vite / esbuild / Rollup chunk fingerprinting**: reconstruct module boundaries and `purl` coordinates from minified JS bundles when `.map` files are omitted in production, using AST structural signatures and export table matching.
- **Chrome/Chromium CRX3 protobuf parser**: in-memory parser for `.crx` extension headers (v3 `CrxFileHeader` protobuf, asymmetric public key proofs, and `manifest.json` CSP/permissions audit).
- **Electron BrowserWindow bytecode and preload scanner**: detect insecure runtime flags (`nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`) inside packed `app.asar` entry points.

### Milestone 2 (`v0.5.0`): source-to-artifact differential verifier (`v1 -> v2` diff and lockfile cross-check)

- **Lockfile-to-binary reconciliation**: cross-verify `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and `bun.lock` against the actual compiled `.asar` / `.crx` / web bundle to flag undeclared injected code and version drift.
- **Release-to-release differential audit (`bundle-provenance diff <v1> <v2>`)**: compute structural deltas between two compiled binary releases (newly introduced `purl` packages, flipped Electron fuse bits, added native `.node` libraries, and new external network endpoints).

### Milestone 3 (`v0.8.0`): mobile and bytecode artifact support (`React Native Hermes HBC` and `WebAssembly`)

- **Hermes bytecode (`.hbc`) parser**: parse React Native Hermes bytecode file headers (magic `0x1f1903c103bc1fc6`, version, string table, and CJS module table) to extract embedded npm package provenance from compiled mobile bundles.
- **WebAssembly (`.wasm`) provenance inspector**: parse WASM custom sections (`producers`, `name`, `sourceMappingURL`, and `cargo-auditable` compressed dependency data) to emit `pkg:cargo/...` and `pkg:npm/...` coordinates.

### Milestone 4 (`v1.0.0`): AboutCode (`PurlDB` / `ScanCode` / `VulnerableCode`) federation and Nixpkgs packaging

- **AboutCode ecosystem integration**: native output schema and batch CLI sync for **AboutCode `PurlDB`** and **`VulnerableCode`** (`ScanCode` JSON compatibility mode) so compiled client artifacts can be indexed directly into federated open package catalogs.
- **EU CRA Annex V technical file generator and SPDX 3.0**: automated generation of `EU Cyber Resilience Act` Module A conformity bundles (`CycloneDX 1.6` + `SPDX 3.0`).
- **Reproducible packaging**: official derivations for `Nixpkgs` (`flake.nix`) and Debian packaging.
