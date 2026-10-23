// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import { createHash } from "node:crypto";
import type { AsarAuditResult, DiscoveredPackage, Finding } from "./types.ts";

interface AsarNode {
  files?: Record<string, AsarNode>;
  offset?: string;
  size?: number;
  unpacked?: boolean;
  executable?: boolean;
  integrity?: {
    algorithm: string;
    hash: string;
    blockSize: number;
    blocks: string[];
  };
}

export function buildNpmPurl(name: string, version: string): string {
  const cleanVer = version.trim().replace(/^[~^]/, "");
  if (name.startsWith("@")) {
    const [scope, pkg] = name.split("/");
    return `pkg:npm/%40${scope.slice(1)}/${pkg}@${cleanVer}`;
  }
  return `pkg:npm/${name}@${cleanVer}`;
}

function sha256Hex(slice: Uint8Array): string {
  return createHash("sha256").update(slice).digest("hex");
}

export function inspectAsarBuffer(buf: Uint8Array, archivePath = "app.asar"): AsarAuditResult {
  if (buf.length < 16) {
    throw new Error(`Invalid ASAR archive (${archivePath}): buffer shorter than 16-byte Chromium Pickle header`);
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const sizePicklePayload = view.getUint32(0, true);
  const headerSize = view.getUint32(4, true);
  const stringPickleSize = view.getUint32(8, true);
  const jsonByteLength = view.getUint32(12, true);

  if (sizePicklePayload !== 4 || jsonByteLength === 0 || 16 + jsonByteLength > buf.length) {
    throw new Error(
      `Malformed ASAR Chromium Pickle header (payload=${sizePicklePayload}, headerSize=${headerSize}, stringPickle=${stringPickleSize}, jsonLen=${jsonByteLength})`,
    );
  }

  const dataBaseOffset = 8 + headerSize;
  if (dataBaseOffset > buf.length) {
    throw new Error(`ASAR header size (${headerSize}) exceeds archive boundary (${buf.length})`);
  }

  const jsonBytes = buf.subarray(16, 16 + jsonByteLength);
  const tree = JSON.parse(new TextDecoder().decode(jsonBytes)) as AsarNode;

  let totalFiles = 0;
  let filesWithIntegrity = 0;
  const nativeBinaries: string[] = [];
  const packagesByPurl = new Map<string, DiscoveredPackage>();
  const findings: Finding[] = [];

  function walk(node: AsarNode, relPath: string): void {
    if (relPath.split("/").includes("..")) {
      findings.push({
        ruleId: "ASAR-001",
        severity: "CRITICAL",
        message: `Path traversal segment detected inside ASAR header tree: ${relPath}`,
        location: `${archivePath}:${relPath}`,
      });
      return;
    }

    if (node.files) {
      for (const [childName, childNode] of Object.entries(node.files)) {
        const nextPath = relPath ? `${relPath}/${childName}` : childName;
        walk(childNode, nextPath);
      }
      return;
    }

    totalFiles++;
    if (node.integrity && Array.isArray(node.integrity.blocks) && node.integrity.blocks.length > 0) {
      filesWithIntegrity++;
    }

    if (/\.(node|dll|dylib|so)$/i.test(relPath)) {
      nativeBinaries.push(relPath);
    }

    const isPackageJson =
      relPath === "package.json" || relPath.endsWith("/package.json");

    if (isPackageJson && !node.unpacked && node.offset !== undefined && typeof node.size === "number") {
      const fileOffset = Number(node.offset);
      const start = dataBaseOffset + fileOffset;
      const end = start + node.size;
      if (Number.isSafeInteger(fileOffset) && fileOffset >= 0 && end <= buf.length && node.size <= 524288) {
        try {
          const slice = buf.subarray(start, end);
          const raw = JSON.parse(new TextDecoder().decode(slice)) as {
            name?: unknown;
            version?: unknown;
            license?: unknown;
          };
          if (typeof raw.name === "string" && typeof raw.version === "string" && raw.name && raw.version) {
            const purl = buildNpmPurl(raw.name, raw.version);
            const license = typeof raw.license === "string" ? raw.license : undefined;
            packagesByPurl.set(purl, {
              name: raw.name,
              version: raw.version,
              purl,
              license,
              sha256: sha256Hex(slice),
              sourcePath: `${archivePath}:${relPath}`,
              origin: "asar-manifest",
            });
          }
        } catch {
          // Ignore malformed non-manifest package.json fixtures
        }
      }
    }
  }

  walk(tree, "");

  const hasIntegrityBlocks = totalFiles > 0 && filesWithIntegrity === totalFiles;
  if (!hasIntegrityBlocks) {
    findings.push({
      ruleId: "ASAR-002",
      severity: "MEDIUM",
      message: `ASAR archive lacks complete per-file SHA-256 block integrity metadata (${filesWithIntegrity}/${totalFiles} files covered)`,
      location: archivePath,
    });
  }

  if (nativeBinaries.length > 0) {
    findings.push({
      ruleId: "ASAR-003",
      severity: "LOW",
      message: `Embedded native binary addons detected (${nativeBinaries.length}): ${nativeBinaries.slice(0, 5).join(", ")}`,
      location: archivePath,
    });
  }

  return {
    headerSize,
    jsonByteLength,
    totalFiles,
    hasIntegrityBlocks,
    nativeBinaries,
    packages: Array.from(packagesByPurl.values()),
    findings,
  };
}
