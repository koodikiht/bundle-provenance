// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import type { Finding, FuseAuditResult, FuseState, FuseStatus } from "./types.ts";

// Official 32-byte Electron Fuse v1 sentinel ("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX")
export const FUSE_SENTINEL = new Uint8Array([
  0x64, 0x4c, 0x37, 0x70, 0x4b, 0x47, 0x64, 0x6e,
  0x4e, 0x7a, 0x37, 0x39, 0x36, 0x50, 0x62, 0x62,
  0x6a, 0x51, 0x57, 0x4e, 0x4b, 0x6d, 0x48, 0x58,
  0x42, 0x5a, 0x61, 0x42, 0x39, 0x74, 0x73, 0x58,
]);

const FUSE_V1_SCHEMA = [
  "RunAsNode",
  "EnableCookieEncryption",
  "EnableNodeOptionsEnvironmentVariable",
  "EnableNodeCliInspectArguments",
  "EnableEmbeddedAsarIntegrityValidation",
  "OnlyLoadAppFromAsar",
  "LoadBrowserProcessSpecificV8Snapshot",
  "GrantFileProtocolExtraPrivileges",
  "WasmTrapHandlers",
] as const;

function decodeFuseByte(b: number): FuseState {
  if (b === 0x30) return "disabled"; // '0'
  if (b === 0x31) return "enabled";  // '1'
  if (b === 0x72) return "removed";  // 'r'
  return "unknown";
}

function findSentinelOffset(buf: Uint8Array): number {
  const limit = buf.length - FUSE_SENTINEL.length - 2;
  outer: for (let i = 0; i <= limit; i++) {
    if (buf[i] !== 0x64 || buf[i + 1] !== 0x4c) continue;
    for (let j = 2; j < FUSE_SENTINEL.length; j++) {
      if (buf[i + j] !== FUSE_SENTINEL[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export function inspectElectronFuses(buf: Uint8Array, location = "binary"): FuseAuditResult {
  const offset = findSentinelOffset(buf);
  if (offset < 0) {
    return {
      found: false,
      sentinelOffsetHex: null,
      version: null,
      wireLength: null,
      fuses: [],
      findings: [],
    };
  }

  const offsetHex = `0x${offset.toString(16).padStart(8, "0")}`;
  const wireStart = offset + FUSE_SENTINEL.length;
  const version = buf[wireStart];
  const wireLength = buf[wireStart + 1];
  const payloadStart = wireStart + 2;

  if (payloadStart + wireLength > buf.length || wireLength === 0 || wireLength > 64) {
    return {
      found: true,
      sentinelOffsetHex: offsetHex,
      version,
      wireLength,
      fuses: [],
      findings: [
        {
          ruleId: "FUSE-000",
          severity: "MEDIUM",
          message: `Truncated or malformed Electron fuse wire block (version=${version}, len=${wireLength})`,
          location,
          offsetHex,
        },
      ],
    };
  }

  const fuses: FuseStatus[] = [];
  for (let idx = 0; idx < wireLength; idx++) {
    const rawByte = buf[payloadStart + idx];
    const name = FUSE_V1_SCHEMA[idx] ?? `Fuse_${idx}`;
    fuses.push({
      name,
      byteIndex: idx,
      rawByte,
      state: decodeFuseByte(rawByte),
    });
  }

  const findings: Finding[] = [];
  const byName = new Map(fuses.map((f) => [f.name, f]));

  if (byName.get("RunAsNode")?.state === "enabled") {
    findings.push({
      ruleId: "FUSE-001",
      severity: "CRITICAL",
      message: "RunAsNode fuse is enabled; binary can be invoked as an arbitrary Node.js interpreter via ELECTRON_RUN_AS_NODE=1",
      location,
      offsetHex,
    });
  }

  if (byName.get("EnableNodeCliInspectArguments")?.state === "enabled") {
    findings.push({
      ruleId: "FUSE-002",
      severity: "HIGH",
      message: "EnableNodeCliInspectArguments is enabled; V8 debugger injection (--inspect) is permitted in production",
      location,
      offsetHex,
    });
  }

  if (byName.get("EnableNodeOptionsEnvironmentVariable")?.state === "enabled") {
    findings.push({
      ruleId: "FUSE-003",
      severity: "HIGH",
      message: "EnableNodeOptionsEnvironmentVariable is enabled; NODE_OPTIONS preload injection is permitted",
      location,
      offsetHex,
    });
  }

  if (byName.get("EnableCookieEncryption")?.state === "disabled") {
    findings.push({
      ruleId: "FUSE-004",
      severity: "MEDIUM",
      message: "EnableCookieEncryption is disabled; Chromium Cookie store is persisted without OS keychain encryption",
      location,
      offsetHex,
    });
  }

  if (byName.get("EnableEmbeddedAsarIntegrityValidation")?.state === "disabled") {
    findings.push({
      ruleId: "FUSE-005",
      severity: "HIGH",
      message: "EnableEmbeddedAsarIntegrityValidation is disabled; app.asar payload tampering is not verified at boot",
      location,
      offsetHex,
    });
  }

  if (byName.get("OnlyLoadAppFromAsar")?.state === "disabled") {
    findings.push({
      ruleId: "FUSE-006",
      severity: "MEDIUM",
      message: "OnlyLoadAppFromAsar is disabled; unpacked resources/app directory can shadow app.asar",
      location,
      offsetHex,
    });
  }

  return {
    found: true,
    sentinelOffsetHex: offsetHex,
    version,
    wireLength,
    fuses,
    findings,
  };
}
