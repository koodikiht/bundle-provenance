<!-- SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht -->

<!-- SPDX-License-Identifier: MIT -->

# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please report vulnerabilities via **GitHub Security Advisories** (`Security -> Advisories -> Report a vulnerability`) or by emailing `contact@koodikiht.dev`.

- **Response SLA**: Initial response within 48 hours.
- **Parser Isolation**: `bundle-provenance` parses untrusted binary headers (`Chromium Pickle`, `Electron Fuses`, `SourceMap v3`) strictly in memory using bounds-checked `DataView` slices without extracting files to the host filesystem or executing embedded scripts.
