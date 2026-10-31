<!-- SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht -->
<!-- SPDX-License-Identifier: MIT -->

# EU Cyber Resilience Act (CRA) Module A conformity statement

Pursuant to **Regulation (EU) 2024/2847 (Cyber Resilience Act), Annex V and Module A (Internal Production Control)**:

1. **Product identification**: `bundle-provenance` (`pkg:github/koodikiht/bundle-provenance@0.1.0`)
2. **Manufacturer / maintainer**: Mark (`malfunctionAI`) / KoodiKiht (Tallinn, Estonia - `contact@koodikiht.dev`)
3. **Supply-chain hygiene**:
   - Runtime dependency count: `0` (eliminates transitive third-party supply-chain exposure).
   - Build provenance: cryptographically attested via **SLSA Build Level 3** (`Sigstore` transparency log via `.github/workflows/release.yml`).
   - Machine-readable SBOM: emitted natively via `bundle-provenance scan --format cyclonedx` (`CycloneDX v1.6`).
4. **Coordinated vulnerability disclosure (CVD)**: documented in `SECURITY.md` with a 48-hour triage SLA.
