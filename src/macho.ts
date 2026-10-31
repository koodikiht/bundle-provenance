// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import type { Finding, FuseAuditResult, MachoEntitlementsAuditResult } from "./types.ts";

// CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 (big-endian in Mach-O LC_CODE_SIGNATURE SuperBlob)
const CSMAGIC_EMBEDDED_ENTITLEMENTS = [0xfa, 0xde, 0x71, 0x71] as const;

const TRACKED_ENTITLEMENTS = [
  "com.apple.security.cs.allow-dyld-environment-variables",
  "com.apple.security.cs.disable-library-validation",
  "com.apple.security.cs.allow-unsigned-executable-memory",
  "com.apple.security.cs.disable-executable-page-protection",
  "com.apple.security.cs.debugger",
  "com.apple.security.get-task-allow",
  "com.apple.security.device.audio-input",
  "com.apple.security.device.microphone",
  "com.apple.security.device.camera",
  "com.apple.security.device.bluetooth",
  "com.apple.security.automation.apple-events",
  "com.apple.security.personal-information.addressbook",
  "com.apple.security.personal-information.calendars",
  "com.apple.security.personal-information.photos-library",
  "com.apple.security.personal-information.location",
] as const;

const TCC_PRIVILEGED_ENTITLEMENTS = [
  "com.apple.security.device.audio-input",
  "com.apple.security.device.microphone",
  "com.apple.security.device.camera",
  "com.apple.security.automation.apple-events",
  "com.apple.security.personal-information.addressbook",
  "com.apple.security.personal-information.calendars",
  "com.apple.security.personal-information.photos-library",
  "com.apple.security.personal-information.location",
] as const;

function findEntitlementBlob(buf: Uint8Array): { offset: number; xml: string } | null {
  const limit = buf.length - 16;
  for (let i = 0; i <= limit; i++) {
    if (
      buf[i] === CSMAGIC_EMBEDDED_ENTITLEMENTS[0] &&
      buf[i + 1] === CSMAGIC_EMBEDDED_ENTITLEMENTS[1] &&
      buf[i + 2] === CSMAGIC_EMBEDDED_ENTITLEMENTS[2] &&
      buf[i + 3] === CSMAGIC_EMBEDDED_ENTITLEMENTS[3]
    ) {
      const length =
        ((buf[i + 4] << 24) >>> 0) |
        (buf[i + 5] << 16) |
        (buf[i + 6] << 8) |
        buf[i + 7];
      if (length > 16 && length <= 65536 && i + length <= buf.length) {
        const xmlBytes = buf.subarray(i + 8, i + length);
        const xml = new TextDecoder().decode(xmlBytes);
        if (xml.includes("<plist") && xml.includes("<dict")) {
          return { offset: i, xml };
        }
      }
    }
  }
  return null;
}

export function parseEntitlementsPlistXml(xml: string): string[] {
  const enabled: string[] = [];
  for (const key of TRACKED_ENTITLEMENTS) {
    const escaped = key.replace(/\./g, "\\.");
    const re = new RegExp(`<key>\\s*${escaped}\\s*</key>\\s*<true\\s*/>`, "i");
    if (re.test(xml)) {
      enabled.push(key);
    }
  }
  return enabled;
}

export function inspectMachoEntitlements(
  buf: Uint8Array,
  location = "Mach-O",
  fusesResult?: FuseAuditResult,
): MachoEntitlementsAuditResult {
  const blob = findEntitlementBlob(buf);
  let offsetHex: string | null = null;
  let xmlText: string | null = null;

  if (blob) {
    offsetHex = `0x${blob.offset.toString(16).padStart(8, "0")}`;
    xmlText = blob.xml;
  } else {
    // Allow direct scanning of standalone entitlements.plist XML files
    const head = new TextDecoder().decode(buf.subarray(0, Math.min(buf.length, 4096)));
    if (head.includes("<plist") && head.includes("com.apple.security")) {
      offsetHex = "0x00000000";
      xmlText = new TextDecoder().decode(buf);
    }
  }

  if (!xmlText) {
    return {
      found: false,
      blobOffsetHex: null,
      enabledEntitlements: [],
      tccEntitlements: [],
      findings: [],
    };
  }

  const enabledEntitlements = parseEntitlementsPlistXml(xmlText);
  const enabledSet = new Set(enabledEntitlements);
  const tccEntitlements = TCC_PRIVILEGED_ENTITLEMENTS.filter((k) => enabledSet.has(k));
  const findings: Finding[] = [];

  const hasDyldEnv = enabledSet.has("com.apple.security.cs.allow-dyld-environment-variables");
  const hasDisableLibVal = enabledSet.has("com.apple.security.cs.disable-library-validation");
  const hasDebugger =
    enabledSet.has("com.apple.security.cs.debugger") ||
    enabledSet.has("com.apple.security.get-task-allow");

  const fuseMap = new Map(fusesResult?.fuses.map((f) => [f.name, f.state]) ?? []);
  const fusesHardened =
    fuseMap.get("RunAsNode") === "disabled" ||
    fuseMap.get("EnableNodeOptionsEnvironmentVariable") === "disabled";

  if (hasDyldEnv && hasDisableLibVal) {
    const fuseNote = fusesHardened
      ? " (bypasses hardened Electron Fuses RunAsNode=disabled / NodeOptions=disabled)"
      : "";
    const tccNote =
      tccEntitlements.length > 0
        ? `; enables unsigned DYLD_INSERT_LIBRARIES injection to inherit TCC entitlements (${tccEntitlements.join(", ")})`
        : "; enables arbitrary unsigned dylib injection via DYLD_INSERT_LIBRARIES";
    findings.push({
      ruleId: "MACHO-001",
      severity: "CRITICAL",
      message: `Mach-O Hardened Runtime allows both 'cs.allow-dyld-environment-variables' and 'cs.disable-library-validation'${fuseNote}${tccNote}`,
      location,
      offsetHex: offsetHex ?? undefined,
    });
  } else if (hasDyldEnv) {
    findings.push({
      ruleId: "MACHO-002",
      severity: "HIGH",
      message:
        "Mach-O entitlement 'com.apple.security.cs.allow-dyld-environment-variables' is enabled; process accepts DYLD_* environment injection across privilege boundaries",
      location,
      offsetHex: offsetHex ?? undefined,
    });
  }

  if (hasDisableLibVal && tccEntitlements.length > 0 && !hasDyldEnv) {
    findings.push({
      ruleId: "MACHO-003",
      severity: "MEDIUM",
      message: `Mach-O entitlement 'cs.disable-library-validation' is enabled alongside TCC privileges (${tccEntitlements.join(", ")}); unsigned plugins/addons can be dlopen'd into the TCC-trusted process`,
      location,
      offsetHex: offsetHex ?? undefined,
    });
  }

  if (hasDebugger) {
    findings.push({
      ruleId: "MACHO-004",
      severity: "HIGH",
      message:
        "Mach-O entitlement 'cs.debugger' or 'get-task-allow' is enabled in release artifact; permits task_for_pid / debugger attachment",
      location,
      offsetHex: offsetHex ?? undefined,
    });
  }

  if (
    fuseMap.get("RunAsNode") === "enabled" &&
    tccEntitlements.length > 0
  ) {
    findings.push({
      ruleId: "MACHO-005",
      severity: "CRITICAL",
      message: `Electron 'RunAsNode' fuse is enabled while Mach-O binary holds macOS TCC entitlements (${tccEntitlements.join(", ")}); local processes can invoke ELECTRON_RUN_AS_NODE=1 to inherit TCC permissions`,
      location,
      offsetHex: offsetHex ?? undefined,
    });
  }

  return {
    found: true,
    blobOffsetHex: offsetHex,
    enabledEntitlements,
    tccEntitlements,
    findings,
  };
}
