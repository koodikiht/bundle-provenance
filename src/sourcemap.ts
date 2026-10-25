// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import { buildNpmPurl } from "./asar.ts";
import type { DiscoveredPackage, Finding, SourceMapAuditResult } from "./types.ts";

interface SourceMapV3 {
  version?: number;
  sources?: unknown[];
  sourcesContent?: unknown[];
}

const NODE_MODULES_RE =
  /(?:^|\/)node_modules\/(?:\.pnpm\/([^/]+)\/node_modules\/)?((?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*)(?:\/|$)/i;

const ENDPOINT_RE = /\b(?:https?|wss):\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s"'`<>\\)]*)?/g;

const IGNORED_HOSTS = new Set([
  "www.w3.org",
  "reactjs.org",
  "developer.mozilla.org",
  "github.com",
  "opensource.org",
  "spdx.org",
  "cyclonedx.org",
  "localhost",
]);

function parsePnpmSegment(pnpmSeg: string | undefined, fallbackName: string): { name: string; version: string } {
  if (pnpmSeg) {
    // e.g. "@scope+pkg@1.2.3" or "lodash@4.17.21_peer"
    const normalized = pnpmSeg.replace(/^\+/, "").replace(/\+/g, "/");
    const atIdx = normalized.lastIndexOf("@");
    if (atIdx > 0) {
      const name = normalized.slice(0, atIdx);
      const rawVer = normalized.slice(atIdx + 1).split("_")[0];
      if (rawVer && /^\d+\.\d+/.test(rawVer)) {
        return { name, version: rawVer };
      }
    }
  }
  return { name: fallbackName, version: "0.0.0-bundled" };
}

export function inspectBundleAndSourceMap(
  bundleCode: string,
  sourceMapJson?: string,
  declaredDependencies?: Record<string, string>,
  location = "bundle.js",
): SourceMapAuditResult {
  const packagesByPurl = new Map<string, DiscoveredPackage>();
  const findings: Finding[] = [];
  const declaredSet = declaredDependencies ? new Set(Object.keys(declaredDependencies)) : null;

  if (sourceMapJson) {
    const parsed = JSON.parse(sourceMapJson) as SourceMapV3;
    if (parsed.version === 3 && Array.isArray(parsed.sources)) {
      for (const item of parsed.sources) {
        if (typeof item !== "string") continue;
        const m = NODE_MODULES_RE.exec(item);
        if (!m) continue;
        const pnpmSeg = m[1];
        const pkgName = m[2];
        const resolved = parsePnpmSegment(pnpmSeg, pkgName);
        const version =
          resolved.version === "0.0.0-bundled" && declaredDependencies?.[resolved.name]
            ? declaredDependencies[resolved.name].replace(/^[~^]/, "")
            : resolved.version;
        const purl = buildNpmPurl(resolved.name, version);
        const undeclared = declaredSet ? !declaredSet.has(resolved.name) : false;

        if (!packagesByPurl.has(purl)) {
          packagesByPurl.set(purl, {
            name: resolved.name,
            version,
            purl,
            sourcePath: `${location}.map:${item}`,
            origin: "sourcemap",
            undeclared,
          });
        }
      }
    }
  }

  // Parse webpack/esbuild/license banner comments (e.g., "@license pkg v1.2.3" or "/*! pkg@1.2.3 */")
  const bannerRe = /@license\s+((?:@[a-z0-9-_]+\/)?[a-z0-9-_.]+)\s+v?(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)/gi;
  let bm: RegExpExecArray | null;
  while ((bm = bannerRe.exec(bundleCode)) !== null) {
    const name = bm[1];
    const version = bm[2];
    const purl = buildNpmPurl(name, version);
    const undeclared = declaredSet ? !declaredSet.has(name) : false;
    if (!packagesByPurl.has(purl)) {
      packagesByPurl.set(purl, {
        name,
        version,
        purl,
        sourcePath: location,
        origin: "bundle-banner",
        undeclared,
      });
    }
  }

  for (const pkg of packagesByPurl.values()) {
    if (pkg.undeclared) {
      findings.push({
        ruleId: "BUNDLE-001",
        severity: "HIGH",
        message: `Phantom (undeclared) package embedded in compiled bundle but absent from declared manifest: ${pkg.purl}`,
        location: pkg.sourcePath,
      });
    }
  }

  const endpointSet = new Set<string>();
  let em: RegExpExecArray | null;
  while ((em = ENDPOINT_RE.exec(bundleCode)) !== null) {
    try {
      const url = new URL(em[0]);
      if (!IGNORED_HOSTS.has(url.hostname)) {
        endpointSet.add(em[0]);
      }
    } catch {
      // skip invalid URL fragments
    }
  }

  return {
    packages: Array.from(packagesByPurl.values()),
    endpoints: Array.from(endpointSet).sort(),
    findings,
  };
}
