#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 Mark (malfunctionAI) / KoodiKiht
// SPDX-License-Identifier: MIT

import {
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { inspectAsarBuffer } from "./asar.ts";
import { inspectElectronFuses } from "./fuses.ts";
import { inspectMachoEntitlements } from "./macho.ts";
import { formatCycloneDx, formatSarif, formatTextSummary } from "./reporters.ts";
import { inspectBundleAndSourceMap } from "./sourcemap.ts";
import type { AuditReport, DiscoveredPackage, Finding } from "./types.ts";

const SKIPPED_HELPERS = new Set([
  "chrome-sandbox",
  "chrome_crashpad_handler",
  "crashpad_handler",
  "squirrel.exe",
]);

function hasNativeExecutableMagic(filePath: string): boolean {
  let fd = -1;
  try {
    fd = openSync(filePath, "r");
    const hdr = new Uint8Array(4);
    if (readSync(fd, hdr, 0, 4, 0) < 4) return false;
    // ELF (0x7f 'E' 'L' 'F'), PE ('M' 'Z'), or Mach-O / Universal fat headers
    if (hdr[0] === 0x7f && hdr[1] === 0x45 && hdr[2] === 0x4c && hdr[3] === 0x46) return true;
    if (hdr[0] === 0x4d && hdr[1] === 0x5a) return true;
    const be = ((hdr[0] << 24) >>> 0) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
    return (
      be === 0xfeedface ||
      be === 0xfeedfacf ||
      be === 0xcefaedfe ||
      be === 0xcffaedfe ||
      be === 0xcafebabe
    );
  } catch {
    return false;
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

export function scanAppBundleDirectory(appDir: string): AuditReport {
  const packages: DiscoveredPackage[] = [];
  const findings: Finding[] = [];
  const endpoints: string[] = [];
  const report: AuditReport = {
    target: appDir,
    timestamp: new Date().toISOString(),
    packages,
    endpoints,
    findings,
  };

  const fuseCandidates = [
    join(appDir, "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"),
    join(appDir, "Contents/Frameworks/Electron Framework.framework/Versions/Current/Electron Framework"),
    join(appDir, "Contents/Frameworks/Electron Framework.framework/Electron Framework"),
  ];

  if (existsSync(appDir)) {
    for (const entry of readdirSync(appDir)) {
      const lower = entry.toLowerCase();
      if (
        SKIPPED_HELPERS.has(lower) ||
        lower.startsWith("lib") ||
        /\.(asar|pak|dat|bin|json|txt|md|html|icns|ico|png|dll|so|dylib)$/i.test(lower) ||
        /\.so\.\d+$/i.test(lower)
      ) {
        continue;
      }
      const full = join(appDir, entry);
      if (existsSync(full) && statSync(full).isFile() && hasNativeExecutableMagic(full)) {
        fuseCandidates.push(full);
      }
    }
  }

  for (const cand of fuseCandidates) {
    if (existsSync(cand) && statSync(cand).isFile()) {
      const fuseRes = inspectElectronFuses(new Uint8Array(readFileSync(cand)), cand);
      if (fuseRes.found) {
        report.fuses = fuseRes;
        findings.push(...fuseRes.findings);
        break;
      }
    }
  }

  const macosDir = join(appDir, "Contents/MacOS");
  if (existsSync(macosDir) && statSync(macosDir).isDirectory()) {
    for (const entry of readdirSync(macosDir)) {
      const fullExec = join(macosDir, entry);
      if (existsSync(fullExec) && statSync(fullExec).isFile()) {
        const machoRes = inspectMachoEntitlements(
          new Uint8Array(readFileSync(fullExec)),
          fullExec,
          report.fuses,
        );
        if (machoRes.found) {
          report.macho = machoRes;
          findings.push(...machoRes.findings);
          break;
        }
      }
    }
  }

  const resDirs = [join(appDir, "Contents/Resources"), join(appDir, "resources")];
  const asarCandidates: string[] = [];
  for (const resDir of resDirs) {
    if (!existsSync(resDir) || !statSync(resDir).isDirectory()) continue;
    for (const rel of ["app.asar", "app/node_modules.asar"]) {
      const p = join(resDir, rel);
      if (!asarCandidates.includes(p)) asarCandidates.push(p);
    }
    for (const entry of readdirSync(resDir)) {
      if (entry.endsWith(".asar")) {
        const full = join(resDir, entry);
        if (!asarCandidates.includes(full)) asarCandidates.push(full);
      }
    }
  }

  for (const asarPath of asarCandidates) {
    if (existsSync(asarPath) && statSync(asarPath).isFile()) {
      const asarRes = inspectAsarBuffer(new Uint8Array(readFileSync(asarPath)), asarPath);
      report.asar = asarRes;
      packages.push(...asarRes.packages);
      findings.push(...asarRes.findings);
      break;
    }
  }

  return report;
}

export function scanArtifactBuffer(
  buf: Uint8Array,
  targetName: string,
  options?: {
    sourceMapJson?: string;
    declaredDependencies?: Record<string, string>;
  },
): AuditReport {
  const packages: DiscoveredPackage[] = [];
  const findings: Finding[] = [];
  const endpoints: string[] = [];

  const report: AuditReport = {
    target: targetName,
    timestamp: new Date().toISOString(),
    packages,
    endpoints,
    findings,
  };

  if (targetName.endsWith(".asar")) {
    const asarRes = inspectAsarBuffer(buf, targetName);
    report.asar = asarRes;
    packages.push(...asarRes.packages);
    findings.push(...asarRes.findings);
    return report;
  }

  if (/\.(js|mjs|cjs)$/i.test(targetName) || options?.sourceMapJson) {
    const text = new TextDecoder().decode(buf);
    const bundleRes = inspectBundleAndSourceMap(
      text,
      options?.sourceMapJson,
      options?.declaredDependencies,
      targetName,
    );
    report.bundle = bundleRes;
    packages.push(...bundleRes.packages);
    endpoints.push(...bundleRes.endpoints);
    findings.push(...bundleRes.findings);
    return report;
  }

  const fuseRes = inspectElectronFuses(buf, targetName);
  report.fuses = fuseRes;
  findings.push(...fuseRes.findings);

  const machoRes = inspectMachoEntitlements(buf, targetName, fuseRes);
  if (machoRes.found) {
    report.macho = machoRes;
    findings.push(...machoRes.findings);
  }

  return report;
}

function printUsage(): void {
  console.log(`bundle-provenance v0.1.0 - Post-build client artifact and SBOM auditor

Usage:
  bundle-provenance scan <file> [--format text|json|cyclonedx|sarif] [--map <file.map>] [--manifest <package.json>] [--fail-on-high]
  bundle-provenance --help
`);
}

const isMain =
  import.meta.main ??
  Boolean(process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href);

if (isMain) {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printUsage();
    process.exit(0);
  }

  const cmd = args[0];
  const target = args[1];
  if (cmd !== "scan" || !target) {
    printUsage();
    process.exit(1);
  }

  let format = "text";
  let mapPath: string | undefined;
  let manifestPath: string | undefined;
  let failOnHigh = false;

  for (let i = 2; i < args.length; i++) {
    if (args[i] === "--format" && args[i + 1]) {
      format = args[++i];
    } else if (args[i] === "--map" && args[i + 1]) {
      mapPath = args[++i];
    } else if (args[i] === "--manifest" && args[i + 1]) {
      manifestPath = args[++i];
    } else if (args[i] === "--fail-on-high") {
      failOnHigh = true;
    }
  }

  const st = statSync(target);
  let report: AuditReport;

  if (st.isDirectory()) {
    report = scanAppBundleDirectory(target);
  } else if (st.isFile()) {
    const rawBuf = new Uint8Array(readFileSync(target));
    const sourceMapJson = mapPath ? readFileSync(mapPath, "utf8") : undefined;
    let declaredDeps: Record<string, string> | undefined;
    if (manifestPath) {
      const pkgJson = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        dependencies?: Record<string, string>;
      };
      declaredDeps = pkgJson.dependencies ?? {};
    }

    report = scanArtifactBuffer(rawBuf, target, {
      sourceMapJson,
      declaredDependencies: declaredDeps,
    });
  } else {
    console.error(`Error: ${target} is neither a regular file nor an .app directory`);
    throw process.exit(1);
  }

  if (format === "cyclonedx") {
    console.log(formatCycloneDx(report));
  } else if (format === "sarif") {
    console.log(formatSarif(report));
  } else if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatTextSummary(report));
  }

  if (
    failOnHigh &&
    report.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
  ) {
    process.exit(2);
  }
}
