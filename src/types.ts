// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type FuseState = "enabled" | "disabled" | "removed" | "unknown";

export interface FuseStatus {
  name: string;
  byteIndex: number;
  rawByte: number;
  state: FuseState;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  location?: string;
  offsetHex?: string;
}

export interface FuseAuditResult {
  found: boolean;
  sentinelOffsetHex: string | null;
  version: number | null;
  wireLength: number | null;
  fuses: FuseStatus[];
  findings: Finding[];
}

export interface DiscoveredPackage {
  name: string;
  version: string;
  purl: string;
  license?: string;
  sha256?: string;
  sourcePath: string;
  origin: "asar-manifest" | "sourcemap" | "bundle-banner";
  undeclared?: boolean;
}

export interface AsarAuditResult {
  headerSize: number;
  jsonByteLength: number;
  totalFiles: number;
  hasIntegrityBlocks: boolean;
  nativeBinaries: string[];
  packages: DiscoveredPackage[];
  findings: Finding[];
}

export interface SourceMapAuditResult {
  packages: DiscoveredPackage[];
  endpoints: string[];
  findings: Finding[];
}

export interface MachoEntitlementsAuditResult {
  found: boolean;
  blobOffsetHex: string | null;
  enabledEntitlements: string[];
  tccEntitlements: string[];
  findings: Finding[];
}

export interface AuditReport {
  target: string;
  timestamp: string;
  fuses?: FuseAuditResult;
  macho?: MachoEntitlementsAuditResult;
  asar?: AsarAuditResult;
  bundle?: SourceMapAuditResult;
  packages: DiscoveredPackage[];
  endpoints: string[];
  findings: Finding[];
}
