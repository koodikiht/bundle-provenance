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

function isFuseStateByte(b: number): boolean {
  return b === 0x30 || b === 0x31 || b === 0x72;
}

interface WireMatch {
  offset: number;
  version: number;
  wireLength: number;
  valid: boolean;
}

function findFuseWireMatches(buf: Uint8Array): WireMatch[] {
  const matches: WireMatch[] = [];
  const limit = buf.length - FUSE_SENTINEL.length - 2;
  outer: for (let i = 0; i <= limit; i++) {
    if (buf[i] !== 0x64 || buf[i + 1] !== 0x4c) continue;
    for (let j = 2; j < FUSE_SENTINEL.length; j++) {
      if (buf[i + j] !== FUSE_SENTINEL[j]) continue outer;
    }
    const wireStart = i + FUSE_SENTINEL.length;
    const version = buf[wireStart];
    const wireLength = buf[wireStart + 1];
    const payloadStart = wireStart + 2;
    if (version !== 1) continue;

    let valid = wireLength > 0 && wireLength <= 32 && payloadStart + wireLength <= buf.length;
    if (valid) {
      for (let k = 0; k < wireLength; k++) {
        if (!isFuseStateByte(buf[payloadStart + k])) {
          valid = false;
          break;
        }
      }
    }
    matches.push({ offset: i, version, wireLength, valid });
  }
  return matches;
}

function evaluateFuseSlice(fuses: FuseStatus[], location: string, offsetHex: string): Finding[] {
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

  return findings;
}

export function inspectElectronFuses(buf: Uint8Array, location = "binary"): FuseAuditResult {
  const matches = findFuseWireMatches(buf);
  if (matches.length === 0) {
    return {
      found: false,
      sentinelOffsetHex: null,
      version: null,
      wireLength: null,
      fuses: [],
      findings: [],
    };
  }

  const validMatches = matches.filter((m) => m.valid);
  if (validMatches.length === 0) {
    const first = matches[0];
    const offsetHex = `0x${first.offset.toString(16).padStart(8, "0")}`;
    return {
      found: true,
      sentinelOffsetHex: offsetHex,
      version: first.version,
      wireLength: first.wireLength,
      fuses: [],
      findings: [
        {
          ruleId: "FUSE-000",
          severity: "MEDIUM",
          message: `Truncated or malformed Electron fuse wire block (version=${first.version}, len=${first.wireLength})`,
          location,
          offsetHex,
        },
      ],
    };
  }

  let primaryFuses: FuseStatus[] = [];
  let primaryOffsetHex = "";
  const seenRuleIds = new Set<string>();
  const findings: Finding[] = [];
  const sliceSignatures = new Set<string>();

  for (let s = 0; s < validMatches.length; s++) {
    const m = validMatches[s];
    const offsetHex = `0x${m.offset.toString(16).padStart(8, "0")}`;
    const payloadStart = m.offset + FUSE_SENTINEL.length + 2;
    const fuses: FuseStatus[] = [];
    let sig = "";

    for (let idx = 0; idx < m.wireLength; idx++) {
      const rawByte = buf[payloadStart + idx];
      const name = FUSE_V1_SCHEMA[idx] ?? `Fuse_${idx}`;
      const state = decodeFuseByte(rawByte);
      fuses.push({ name, byteIndex: idx, rawByte, state });
      sig += String.fromCharCode(rawByte);
    }

    sliceSignatures.add(sig);
    if (s === 0) {
      primaryFuses = fuses;
      primaryOffsetHex = offsetHex;
    }

    for (const f of evaluateFuseSlice(fuses, location, offsetHex)) {
      if (!seenRuleIds.has(f.ruleId)) {
        seenRuleIds.add(f.ruleId);
        findings.push(f);
      }
    }
  }

  if (sliceSignatures.size > 1) {
    const secondHex = `0x${validMatches[1].offset.toString(16).padStart(8, "0")}`;
    findings.push({
      ruleId: "FUSE-007",
      severity: "HIGH",
      message: `Universal binary fuse vectors diverge across architecture slices (${primaryOffsetHex} vs ${secondHex})`,
      location,
      offsetHex: secondHex,
    });
  }

  return {
    found: true,
    sentinelOffsetHex: primaryOffsetHex,
    version: validMatches[0].version,
    wireLength: validMatches[0].wireLength,
    fuses: primaryFuses,
    findings,
  };
}
