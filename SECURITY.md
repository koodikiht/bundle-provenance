<!-- SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht -->
<!-- SPDX-License-Identifier: MIT -->

# Security policy

## Supported versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a vulnerability

Please report vulnerabilities via **GitHub Security Advisories** (`Security -> Advisories -> Report a vulnerability`) or by emailing `contact@koodikiht.dev`.

- **Response SLA**: initial response within 48 hours.
- **Parser isolation**: `bundle-provenance` parses untrusted binary headers (`Chromium Pickle`, `Electron Fuses`, `SourceMap v3`) strictly in memory using bounds-checked `DataView` slices without extracting files to the host filesystem or executing embedded scripts.
