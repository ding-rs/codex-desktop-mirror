import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";

import {
  SCHEMA_VERSION,
  assertPublishedManifestEnvelope,
  assertStagedAssets,
  buildSyncPlan,
  createManifestDigest,
  createReleaseTag,
} from "./snapshot.mjs";

const REQUIRED_SOURCE_METHODS = ["probe", "stageChanged"];
const REQUIRED_RELEASE_METHODS = [
  "readLatestManifest",
  "stagePrevious",
  "writeMetadata",
  "createDraft",
  "uploadAll",
  "verifyDraft",
  "publishDraft",
  "deleteDraft",
];

function codeUnitCompare(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function assertNonEmptyUniqueIds(expectedIds) {
  if (!Array.isArray(expectedIds) || expectedIds.length === 0) {
    throw new Error("expectedIds must be a non-empty array");
  }
  const seen = new Set();
  for (let index = 0; index < expectedIds.length; index += 1) {
    const id = expectedIds[index];
    if (
      !Object.hasOwn(expectedIds, index) ||
      typeof id !== "string" ||
      id.trim().length === 0 ||
      seen.has(id)
    ) {
      throw new Error("expectedIds must contain exact unique non-empty strings");
    }
    seen.add(id);
  }
}

function assertMethods(value, methods, label) {
  if (!value || typeof value !== "object") {
    throw new Error(`${label} must be an object with required methods`);
  }
  for (const method of methods) {
    if (typeof value[method] !== "function") {
      throw new Error(`${label}.${method} must be a function`);
    }
  }
}

function validateInputs({
  product,
  expectedIds,
  now,
  workDir,
  source,
  releases,
  logger,
}) {
  if (typeof product !== "string" || product.trim().length === 0) {
    throw new Error("product must be a non-empty string");
  }
  if (
    !(now instanceof Date) ||
    Number.isNaN(Date.prototype.getTime.call(now))
  ) {
    throw new Error("now must be a valid Date");
  }
  assertNonEmptyUniqueIds(expectedIds);
  if (typeof workDir !== "string" || workDir.length === 0) {
    throw new Error("workDir must be a non-empty string");
  }
  if (typeof logger !== "function") {
    throw new TypeError("logger must be a function");
  }
  assertMethods(source, REQUIRED_SOURCE_METHODS, "source");
  assertMethods(releases, REQUIRED_RELEASE_METHODS, "releases");
}

function snapshotProbes(probes) {
  if (!Array.isArray(probes)) {
    throw new TypeError("probe must be an array");
  }
  const snapshots = [];
  for (let index = 0; index < probes.length; index += 1) {
    if (!Object.hasOwn(probes, index)) {
      throw new Error("probe array must not be sparse");
    }
    const candidate = probes[index];
    snapshots.push(
      Object.freeze({
        id: candidate?.id,
        filename: candidate?.filename,
        sourceEndpoint: candidate?.sourceEndpoint,
        sourceFingerprint: candidate?.sourceFingerprint,
        resolvedUrl: candidate?.resolvedUrl,
        expectedSize: candidate?.expectedSize,
      }),
    );
  }
  return Object.freeze(snapshots);
}

function assertSafeProbeContract(probes) {
  const filenames = new Set();
  for (const probe of probes) {
    const filename = probe?.filename;
    if (
      typeof filename !== "string" ||
      filename.trim() !== filename ||
      filename.length === 0 ||
      filename === "." ||
      filename === ".." ||
      filename.includes("/") ||
      filename.includes("\\") ||
      filename.includes("\0")
    ) {
      throw new Error(`${String(probe?.id)} probe filename must be a safe basename`);
    }
    if (filenames.has(filename)) {
      throw new Error(`duplicate probe filename: ${filename}`);
    }
    filenames.add(filename);
    if (
      typeof probe.sourceEndpoint !== "string" ||
      probe.sourceEndpoint.length === 0
    ) {
      throw new Error(`${String(probe?.id)} sourceEndpoint must be non-empty`);
    }
  }
}

function stableAsset(probe, measured, destination) {
  return {
    id: probe.id,
    filename: probe.filename,
    sourceEndpoint: probe.sourceEndpoint,
    sourceFingerprint: probe.sourceFingerprint,
    size: measured.size,
    sha256: measured.sha256,
    path: destination,
  };
}

function assertPreviousSnapshot(previous, product, expectedIds) {
  if (previous === null) return;
  if (
    !previous ||
    typeof previous !== "object" ||
    typeof previous.tag !== "string"
  ) {
    throw new Error("previous release tag and manifest are required");
  }
  assertPublishedManifestEnvelope(previous.manifest, {
    expectedIds,
    product,
    tag: previous.tag,
  });
}

async function measureRegularFile(path) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error("staged destination must be a regular file, not a symlink");
  }
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    size += chunk.length;
    hash.update(chunk);
  }
  const after = await lstat(path);
  if (
    !after.isFile() ||
    after.isSymbolicLink() ||
    after.size !== before.size ||
    after.size !== size
  ) {
    throw new Error("staged regular file changed while hashing");
  }
  return { size, sha256: hash.digest("hex") };
}

function manifestAsset(asset) {
  return {
    id: asset.id,
    filename: asset.filename,
    sourceEndpoint: asset.sourceEndpoint,
    sourceFingerprint: asset.sourceFingerprint,
    size: asset.size,
    sha256: asset.sha256,
  };
}

async function cleanupAfterFailure(releases, tag, operationError) {
  try {
    await releases.deleteDraft(tag);
  } catch (cleanupError) {
    throw new AggregateError(
      [operationError, cleanupError],
      "release operation and draft cleanup both failed",
    );
  }
  throw operationError;
}

export async function synchronize({
  product,
  expectedIds,
  now,
  workDir,
  source,
  releases,
  logger = () => {},
}) {
  validateInputs({
    product,
    expectedIds,
    now,
    workDir,
    source,
    releases,
    logger,
  });
  await mkdir(workDir, { recursive: true });
  if ((await readdir(workDir)).length !== 0) {
    throw new Error("workDir must be empty before synchronization");
  }

  const previous = await releases.readLatestManifest(expectedIds);
  assertPreviousSnapshot(previous, product, expectedIds);
  logger("probe");
  const currentProbes = snapshotProbes(await source.probe());
  logger("compare");
  const plan = buildSyncPlan(
    previous?.manifest ?? null,
    currentProbes,
    expectedIds,
  );
  assertSafeProbeContract(currentProbes);
  if (!plan.hasChanges) return { status: "no-changes" };

  const changedIds = new Set(plan.changedIds);
  const previousById = new Map(
    (previous?.manifest?.assets ?? []).map((asset) => [asset.id, asset]),
  );
  const staged = [];
  for (const probe of currentProbes) {
    const destination = join(workDir, probe.filename);
    logger(`stage ${probe.id}`);
    if (changedIds.has(probe.id)) {
      await source.stageChanged(probe, destination);
    } else {
      await releases.stagePrevious(
          previous.tag,
          previousById.get(probe.id),
          destination,
        );
    }
    const measured = await measureRegularFile(destination);
    logger(`hash ${probe.id}`);
    staged.push(stableAsset(probe, measured, destination));
  }
  assertStagedAssets(staged, expectedIds);

  const manifestDigest = createManifestDigest(product, staged);
  const releaseTag = createReleaseTag(now, manifestDigest);
  const manifest = {
    schemaVersion: SCHEMA_VERSION,
    product,
    generatedAt: Date.prototype.toISOString.call(now),
    releaseTag,
    manifestDigest,
    assets: staged
      .map(manifestAsset)
      .sort((left, right) => codeUnitCompare(left.id, right.id)),
  };
  await releases.writeMetadata(workDir, manifest, staged);

  let draftCreated = false;
  try {
    logger("draft");
    const createResult = await releases.createDraft(
      releaseTag,
      manifest,
      workDir,
      staged,
    );
    if (createResult?.alreadyPublished === true) {
      return { status: "published", tag: releaseTag, manifest };
    }
    draftCreated = true;
    logger("upload");
    await releases.uploadAll(releaseTag, workDir, staged);
    logger("verify");
    await releases.verifyDraft(releaseTag, manifest, staged);
    logger("publish");
    await releases.publishDraft(releaseTag);
  } catch (error) {
    const shouldCleanup =
      !error?.releasePublished &&
      !error?.publishStateUnknown &&
      (draftCreated || error?.draftCreated);
    if (shouldCleanup) {
      return await cleanupAfterFailure(releases, releaseTag, error);
    }
    throw error;
  }

  return { status: "published", tag: releaseTag, manifest };
}
