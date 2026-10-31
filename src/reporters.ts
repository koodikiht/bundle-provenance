// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import { randomUUID } from "node:crypto";
import type { AuditReport, Severity } from "./types.ts";

export function formatCycloneDx(report: AuditReport): string {
  const components = report.packages.map((pkg) => {
    const comp: Record<string, unknown> = {
      type: "library",
      name: pkg.name,
      version: pkg.version,
      purl: pkg.purl,
      properties: [
        { name: "bundle-provenance:origin", value: pkg.origin },
        { name: "bundle-provenance:sourcePath", value: pkg.sourcePath },
      ],
    };
    if (pkg.license) {
      comp.licenses = [{ license: { id: pkg.license } }];
    }
    if (pkg.sha256) {
      comp.hashes = [{ alg: "SHA-256", content: pkg.sha256 }];
    }
    if (pkg.undeclared) {
      (comp.properties as Array<{ name: string; value: string }>).push({
        name: "bundle-provenance:undeclared",
        value: "true",
      });
    }
    return comp;
  });

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.timestamp,
      tools: {
        components: [
          {
            type: "application",
            name: "bundle-provenance",
            version: "0.1.0",
            supplier: { name: "KoodiKiht" },
          },
        ],
      },
      component: {
        type: "application",
        name: report.target,
      },
    },
    components,
  };

  return JSON.stringify(bom, null, 2);
}

function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "CRITICAL" || sev === "HIGH") return "error";
  if (sev === "MEDIUM") return "warning";
  return "note";
}

export function formatSarif(report: AuditReport): string {
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "bundle-provenance",
            version: "0.1.0",
            informationUri: "https://github.com/koodikiht/bundle-provenance",
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location ?? report.target },
              },
            },
          ],
          properties: f.offsetHex ? { offsetHex: f.offsetHex, severity: f.severity } : { severity: f.severity },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatTextSummary(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`=== bundle-provenance v0.1.0 | target: ${report.target} ===`);

  if (report.fuses?.found) {
    lines.push(
      `[FUSES] Sentinel @ ${report.fuses.sentinelOffsetHex} (v${report.fuses.version}, ${report.fuses.wireLength} slots)`,
    );
    for (const f of report.fuses.fuses) {
      lines.push(`  - ${f.name.padEnd(40)} : ${f.state.toUpperCase()}`);
    }
  }

  if (report.macho?.found) {
    lines.push(
      `[MACHO] Embedded Entitlements @ ${report.macho.blobOffsetHex} (${report.macho.enabledEntitlements.length} enabled, ${report.macho.tccEntitlements.length} TCC)`,
    );
    for (const ent of report.macho.enabledEntitlements) {
      lines.push(`  - ${ent}`);
    }
  }

  if (report.asar) {
    lines.push(
      `[ASAR]  Header: ${report.asar.headerSize}B | Files: ${report.asar.totalFiles} | BlockIntegrity: ${report.asar.hasIntegrityBlocks ? "YES" : "NO"} | NativeAddons: ${report.asar.nativeBinaries.length}`,
    );
  }

  lines.push(`[PURL]  Discovered embedded packages: ${report.packages.length}`);
  for (const p of report.packages) {
    const flag = p.undeclared ? " [UNDECLARED]" : "";
    lines.push(`  - ${p.purl} (${p.origin})${flag}`);
  }

  if (report.endpoints.length > 0) {
    lines.push(`[NET]   Hardcoded external endpoints: ${report.endpoints.length}`);
    for (const ep of report.endpoints) {
      lines.push(`  - ${ep}`);
    }
  }

  lines.push(`[AUDIT] Security and provenance findings: ${report.findings.length}`);
  for (const finding of report.findings) {
    lines.push(`  - [${finding.severity}] ${finding.ruleId}: ${finding.message}`);
  }

  return lines.join("\n");
}
