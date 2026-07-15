import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { createCodexSource } from "./lib/codex-sources.mjs";
import { createGitHubReleaseAdapter } from "./lib/github-releases.mjs";
import { synchronize } from "./lib/synchronize.mjs";

const execFileAsync = promisify(execFile);
const EXPECTED_IDS = [
  "darwin-arm64-dmg",
  "darwin-x64-dmg",
  "win32-x64-msix",
  "win32-x64-installer",
];

function runOwnershipToken(env) {
  const runId = env.GITHUB_RUN_ID;
  const runAttempt = env.GITHUB_RUN_ATTEMPT;
  if (/^\d+$/.test(runId ?? "") && /^\d+$/.test(runAttempt ?? "")) {
    return `github-${runId}-${runAttempt}`;
  }
  return `local-${randomUUID()}`;
}

export async function verifyWindowsSignature(
  path,
  { execFileImpl = execFileAsync } = {},
) {
  if (typeof execFileImpl !== "function") {
    throw new TypeError("execFileImpl must be a function");
  }
  try {
    await execFileImpl("signtool", ["verify", "/pa", "/all", path], {
      windowsHide: true,
    });
  } catch {
    throw new Error("Windows signature verification failed");
  }
}

function safeProbe(probe) {
  return {
    id: probe.id,
    filename: probe.filename,
    sourceEndpoint: probe.sourceEndpoint,
    sourceFingerprint: probe.sourceFingerprint,
    ...(probe.expectedSize === undefined
      ? {}
      : { expectedSize: probe.expectedSize }),
  };
}

export async function main({
  argv = process.argv.slice(2),
  env = process.env,
  fetchImpl = fetch,
  execFileImpl = execFileAsync,
  stdout = (line) => console.log(line),
  stderr = (line) => console.error(line),
} = {}) {
  const normalizedArgv = argv[0] === "--" ? argv.slice(1) : argv;
  const unknown = normalizedArgv.filter(
    (argument) => argument !== "--probe-only",
  );
  if (unknown.length > 0 || normalizedArgv.length > 1) {
    throw new Error("usage: pnpm sync [-- --probe-only]");
  }
  const probeOnly = normalizedArgv[0] === "--probe-only";
  const signatureVerifier = (path) =>
    verifyWindowsSignature(path, { execFileImpl });
  const source = createCodexSource({
    fetchImpl,
    verifyWindowsSignature: signatureVerifier,
  });

  if (probeOnly) {
    const currentProbes = await source.probe();
    stdout(JSON.stringify(currentProbes.map(safeProbe), null, 2));
    return { status: "probe-only", probes: currentProbes.map(safeProbe) };
  }

  const token = env.GH_TOKEN;
  const repo = env.GH_REPO;
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GH_TOKEN is required for synchronization");
  }
  if (typeof repo !== "string" || repo.length === 0) {
    throw new Error("GH_REPO is required for synchronization");
  }

  const releases = createGitHubReleaseAdapter({
    repo,
    token,
    execFileImpl,
    runToken: runOwnershipToken(env),
  });
  const workDir = await mkdtemp(join(tmpdir(), "codex-desktop-sync-"));
  try {
    const result = await synchronize({
      product: "codex-desktop",
      expectedIds: EXPECTED_IDS,
      now: new Date(),
      workDir,
      source,
      releases,
      logger: (phase) => stderr(`[sync] ${phase}`),
    });
    stdout(JSON.stringify({ status: result.status, tag: result.tag }));
    return result;
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

function isMain(metaUrl) {
  if (typeof process.argv[1] !== "string") return false;
  return metaUrl === pathToFileURL(resolve(process.argv[1])).href;
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack ?? String(error));
    process.exitCode = 1;
  });
}
