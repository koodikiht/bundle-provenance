// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { inspectAsarBuffer } from "../src/asar.ts";
import { scanArtifactBuffer } from "../src/cli.ts";
import { FUSE_SENTINEL, inspectElectronFuses } from "../src/fuses.ts";
import { inspectMachoEntitlements } from "../src/macho.ts";
import { formatCycloneDx, formatSarif } from "../src/reporters.ts";
import { inspectBundleAndSourceMap } from "../src/sourcemap.ts";

function buildSyntheticBinaryWithFuses(states: string): Uint8Array {
  const prefix = new Uint8Array(64);
  prefix.fill(0x90);
  const wireBytes = new TextEncoder().encode(states);
  const out = new Uint8Array(prefix.length + FUSE_SENTINEL.length + 2 + wireBytes.length + 32);
  out.set(prefix, 0);
  out.set(FUSE_SENTINEL, prefix.length);
  out[prefix.length + FUSE_SENTINEL.length] = 1; // version 1
  out[prefix.length + FUSE_SENTINEL.length + 1] = wireBytes.length;
  out.set(wireBytes, prefix.length + FUSE_SENTINEL.length + 2);
  return out;
}

function buildSyntheticAsarArchive(): Uint8Array {
  const pkgA = new TextEncoder().encode(
    JSON.stringify({ name: "elliptic", version: "6.5.4", license: "MIT" }),
  );
  const pkgB = new TextEncoder().encode(
    JSON.stringify({ name: "@noble/curves", version: "1.4.0", license: "MIT" }),
  );
  const nativeStub = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]);

  const treeObj = {
    files: {
      "package.json": {
        offset: "0",
        size: pkgA.byteLength,
        integrity: {
          algorithm: "SHA256",
          hash: "deadbeef",
          blockSize: 4194304,
          blocks: ["deadbeef"],
        },
      },
      node_modules: {
        files: {
          "@noble": {
            files: {
              curves: {
                files: {
                  "package.json": {
                    offset: String(pkgA.byteLength),
                    size: pkgB.byteLength,
                  },
                },
              },
            },
          },
          keytar: {
            files: {
              "keytar.node": {
                offset: String(pkgA.byteLength + pkgB.byteLength),
                size: nativeStub.byteLength,
              },
            },
          },
        },
      },
    },
  };

  const jsonBytes = new TextEncoder().encode(JSON.stringify(treeObj));
  const paddedJsonLen = Math.ceil(jsonBytes.byteLength / 4) * 4;
  const stringPickleSize = 4 + paddedJsonLen;
  const headerSize = 4 + stringPickleSize;

  const totalLen = 8 + headerSize + pkgA.byteLength + pkgB.byteLength + nativeStub.byteLength;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);

  view.setUint32(0, 4, true);
  view.setUint32(4, headerSize, true);
  view.setUint32(8, stringPickleSize, true);
  view.setUint32(12, jsonBytes.byteLength, true);
  buf.set(jsonBytes, 16);

  const dataStart = 8 + headerSize;
  buf.set(pkgA, dataStart);
  buf.set(pkgB, dataStart + pkgA.byteLength);
  buf.set(nativeStub, dataStart + pkgA.byteLength + pkgB.byteLength);

  return buf;
}

describe("bundle-provenance v0.1.0 core verification", () => {
  test("detects insecure Electron Fuse v1 bitmask and reports exact offset", () => {
    // RunAsNode=1, CookieEnc=0, NodeOpts=1,CliInspect=1, AsarIntegrity=0, OnlyAsar=0, V8Snap=0, FilePriv=1
    const bin = buildSyntheticBinaryWithFuses("10110001");
    const res = inspectElectronFuses(bin, "TestApp.bin");

    expect(res.found).toBe(true);
    expect(res.sentinelOffsetHex).toBe("0x00000040");
    expect(res.version).toBe(1);
    expect(res.wireLength).toBe(8);
    expect(res.fuses[0]?.name).toBe("RunAsNode");
    expect(res.fuses[0]?.state).toBe("enabled");
    expect(res.findings.map((f) => f.ruleId)).toEqual([
      "FUSE-001",
      "FUSE-002",
      "FUSE-003",
      "FUSE-004",
      "FUSE-005",
      "FUSE-006",
    ]);
  });

  test("passes hardened Electron Fuse v1 configuration without findings", () => {
    // RunAsNode=0, CookieEnc=1, NodeOpts=0, CliInspect=0, AsarIntegrity=1, OnlyAsar=1, V8Snap=1, FilePriv=0
    const bin = buildSyntheticBinaryWithFuses("01001110");
    const res = inspectElectronFuses(bin, "HardenedApp.bin");

    expect(res.found).toBe(true);
    expect(res.findings.length).toBe(0);
  });

  test("parses Chromium Pickle ASAR header in-memory and extracts PURLs and native addons", () => {
    const asar = buildSyntheticAsarArchive();
    const res = inspectAsarBuffer(asar, "app.asar");

    expect(res.totalFiles).toBe(3);
    expect(res.hasIntegrityBlocks).toBe(false);
    expect(res.nativeBinaries).toEqual(["node_modules/keytar/keytar.node"]);
    expect(res.packages.map((p) => p.purl)).toEqual([
      "pkg:npm/elliptic@6.5.4",
      "pkg:npm/%40noble/curves@1.4.0",
    ]);
    expect(res.packages[0]?.sha256).toHaveLength(64);
    expect(res.findings.map((f) => f.ruleId)).toContain("ASAR-002");
    expect(res.findings.map((f) => f.ruleId)).toContain("ASAR-003");
  });

  test("reconstructs SourceMap v3 lineage, flags phantom dependencies, and extracts endpoints", () => {
    const code = `
      /*! @license axios v1.7.2 */
      const url = "https://ingest.telemetry-shadow.io/v1/collect";
      const ws = "wss://relay.wallet-node.net:8443/stream";
    `;
    const map = JSON.stringify({
      version: 3,
      sources: [
        "../node_modules/.pnpm/zod@3.23.8/node_modules/zod/lib/index.mjs",
        "../node_modules/.pnpm/+@scure+bip39@1.3.0/node_modules/@scure/bip39/index.js",
      ],
    });

    const res = inspectBundleAndSourceMap(
      code,
      map,
      { zod: "^3.23.8" }, // @scure/bip39 and axios are undeclared!
      "dist/main.js",
    );

    expect(res.packages.map((p) => p.purl)).toEqual([
      "pkg:npm/zod@3.23.8",
      "pkg:npm/%40scure/bip39@1.3.0",
      "pkg:npm/axios@1.7.2",
    ]);
    const undeclared = res.packages.filter((p) => p.undeclared).map((p) => p.name);
    expect(undeclared).toEqual(["@scure/bip39", "axios"]);
    expect(res.endpoints).toEqual([
      "https://ingest.telemetry-shadow.io/v1/collect",
      "wss://relay.wallet-node.net:8443/stream",
    ]);
    expect(res.findings.filter((f) => f.ruleId === "BUNDLE-001").length).toBe(2);
  });

  test("emits valid CycloneDX v1.6 and SARIF v2.1.0 schemas", () => {
    const asar = buildSyntheticAsarArchive();
    const report = scanArtifactBuffer(asar, "release.asar");

    const cdx = JSON.parse(formatCycloneDx(report));
    expect(cdx.bomFormat).toBe("CycloneDX");
    expect(cdx.specVersion).toBe("1.6");
    expect(cdx.components.length).toBe(2);

    const sarif = JSON.parse(formatSarif(report));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  test("detects Mach-O CSMAGIC_EMBEDDED_ENTITLEMENTS DYLD + TCC bypass even when Electron Fuses are hardened", () => {
    const plistXml = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
  <key>com.apple.security.device.camera</key><true/>
  <key>com.apple.security.device.audio-input</key><true/>
</dict></plist>`;
    const xmlBytes = new TextEncoder().encode(plistXml);
    const blobLen = 8 + xmlBytes.byteLength;
    const machoStub = new Uint8Array(32 + blobLen + 16);
    machoStub.set([0xfa, 0xde, 0x71, 0x71], 32);
    const view = new DataView(machoStub.buffer);
    view.setUint32(36, blobLen, false); // big-endian
    machoStub.set(xmlBytes, 40);

    const hardenedFuses = inspectElectronFuses(buildSyntheticBinaryWithFuses("01001110"), "Framework");
    const res = inspectMachoEntitlements(machoStub, "Contents/MacOS/App", hardenedFuses);

    expect(res.found).toBe(true);
    expect(res.blobOffsetHex).toBe("0x00000020");
    expect(res.tccEntitlements).toEqual([
      "com.apple.security.device.audio-input",
      "com.apple.security.device.camera",
    ]);
    expect(res.findings.map((f) => f.ruleId)).toContain("MACHO-001");
    expect(res.findings[0]?.message).toContain("bypasses hardened Electron Fuses");
  });
});
