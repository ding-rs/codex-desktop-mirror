import { createHash } from "node:crypto";

export const SCHEMA_VERSION = 1;

export const MAX_ASSET_SIZE = 2 * 1024 ** 3;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function assertArray(value, field) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${field} must be an array`);
  }
}

function assertExpectedIds(expectedIds) {
  assertArray(expectedIds, "expectedIds");
  for (let index = 0; index < expectedIds.length; index += 1) {
    const id = expectedIds[index];
    if (
      !Object.hasOwn(expectedIds, index) ||
      typeof id !== "string" ||
      id.trim().length === 0
    ) {
      throw new Error(
        `expectedIds logical ID at index ${index} must be a non-empty string`,
      );
    }
  }
}

function assertExactUniqueIds(items, expectedIds, label) {
  assertArray(items, label);
  assertExpectedIds(expectedIds);

  const expectedSet = new Set(expectedIds);
  if (expectedSet.size !== expectedIds.length) {
    throw new Error("expectedIds logical IDs must be unique");
  }

  const actualSet = new Set();
  for (const item of items) {
    const id = item?.id;
    if (actualSet.has(id)) {
      throw new Error(`duplicate ${label} id: ${String(id)}`);
    }
    actualSet.add(id);
  }

  if (
    actualSet.size !== expectedSet.size ||
    [...actualSet].some((id) => !expectedSet.has(id))
  ) {
    const missing = expectedIds.filter((id) => !actualSet.has(id));
    const extra = [...actualSet].filter((id) => !expectedSet.has(id));
    throw new Error(
      `${label} ids do not match expected asset ids` +
        ` (missing: ${missing.join(", ") || "none"};` +
        ` extra: ${extra.join(", ") || "none"})`,
    );
  }
}

function assertSourceFingerprint(asset) {
  if (
    typeof asset.sourceFingerprint !== "string" ||
    asset.sourceFingerprint.length === 0
  ) {
    throw new Error(`${asset.id} sourceFingerprint must be a non-empty string`);
  }
}

function assertAssetSize(asset) {
  if (!Number.isSafeInteger(asset.size) || asset.size <= 0) {
    throw new Error(`${asset.id} size must be a positive safe integer`);
  }
  if (asset.size >= MAX_ASSET_SIZE) {
    throw new Error(`${asset.id} size must be less than 2 GiB`);
  }
}

function assertSha256(asset) {
  if (
    typeof asset.sha256 !== "string" ||
    !SHA256_PATTERN.test(asset.sha256)
  ) {
    throw new Error(
      `${asset.id} sha256 must be a string of 64 lowercase hex characters`,
    );
  }
}

function assertUniqueFilename(asset, filenames) {
  const filename = asset.filename;
  if (
    typeof filename !== "string" ||
    filename.trim().length === 0 ||
    filename !== filename.trim() ||
    filename === "." ||
    filename === ".." ||
    filename.includes("/") ||
    filename.includes("\\") ||
    filename.includes("\0")
  ) {
    throw new Error(`${asset.id} filename must be a safe basename`);
  }
  if (filenames.has(filename)) {
    throw new Error(`duplicate filename: ${filename}`);
  }
  filenames.add(filename);
}

function assertSourceEndpoint(asset) {
  if (
    typeof asset.sourceEndpoint !== "string" ||
    asset.sourceEndpoint.length === 0
  ) {
    throw new Error(`${asset.id} sourceEndpoint must be a non-empty string`);
  }
}

export function assertPreviousManifest(manifest, expectedIds) {
  if (manifest === null) {
    return;
  }
  if (typeof manifest !== "object" || manifest === undefined) {
    throw new TypeError("manifest must be an object or null");
  }
  if (manifest.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `schemaVersion must be ${SCHEMA_VERSION}; received ${String(manifest.schemaVersion)}`,
    );
  }

  assertExactUniqueIds(manifest.assets, expectedIds, "manifest asset");
  const filenames = new Set();
  for (const asset of manifest.assets) {
    assertUniqueFilename(asset, filenames);
    assertSourceEndpoint(asset);
    assertSourceFingerprint(asset);
    assertAssetSize(asset);
    assertSha256(asset);
  }
}

export function assertPublishedManifestEnvelope(
  manifest,
  { expectedIds, product, tag },
) {
  if (typeof product !== "string" || product.trim().length === 0) {
    throw new Error("product must be a non-empty string");
  }
  if (typeof tag !== "string" || tag.length === 0) {
    throw new Error("published release tag must be a non-empty string");
  }
  assertPreviousManifest(manifest, expectedIds);
  if (manifest.product !== product) {
    throw new Error("published manifest product does not match product");
  }
  if (manifest.releaseTag !== tag) {
    throw new Error("published manifest releaseTag does not match release tag");
  }
  if (typeof manifest.generatedAt !== "string") {
    throw new Error("published manifest generatedAt must be canonical ISO");
  }
  const generatedAt = new Date(manifest.generatedAt);
  if (
    Number.isNaN(generatedAt.getTime()) ||
    generatedAt.toISOString() !== manifest.generatedAt
  ) {
    throw new Error("published manifest generatedAt must be canonical ISO");
  }
  if (
    typeof manifest.manifestDigest !== "string" ||
    !SHA256_PATTERN.test(manifest.manifestDigest)
  ) {
    throw new Error("published manifest manifestDigest is invalid");
  }
  const actualDigest = createManifestDigest(product, manifest.assets);
  if (actualDigest !== manifest.manifestDigest) {
    throw new Error("published manifest manifestDigest does not match assets");
  }
  if (createReleaseTag(generatedAt, actualDigest) !== tag) {
    throw new Error(
      "published release tag does not match generatedAt and manifestDigest",
    );
  }
}

export function buildSyncPlan(previousManifest, probes, expectedIds) {
  assertExactUniqueIds(probes, expectedIds, "probe");
  for (const probe of probes) {
    assertSourceFingerprint(probe);
  }
  assertPreviousManifest(previousManifest, expectedIds);

  const previousAssets = new Map(
    (previousManifest?.assets ?? []).map((asset) => [asset.id, asset]),
  );
  const changedIds = [];
  const unchangedIds = [];

  for (const probe of probes) {
    const previousAsset = previousAssets.get(probe.id);
    const destination =
      previousAsset?.sourceFingerprint === probe.sourceFingerprint
        ? unchangedIds
        : changedIds;
    destination.push(probe.id);
  }

  return {
    hasChanges: changedIds.length > 0,
    changedIds,
    unchangedIds,
  };
}

export function assertStagedAssets(assets, expectedIds) {
  assertExactUniqueIds(assets, expectedIds, "staged asset");

  const filenames = new Set();
  for (const asset of assets) {
    assertUniqueFilename(asset, filenames);
    assertSourceEndpoint(asset);
    assertSourceFingerprint(asset);
    assertAssetSize(asset);
    assertSha256(asset);
  }
}

export function canonicalDigestInput(product, assets) {
  const canonicalAssets = [...assets]
    .sort((left, right) => {
      if (left.id === right.id) {
        return 0;
      }
      return left.id < right.id ? -1 : 1;
    })
    .map(
      ({
        id,
        filename,
        sourceEndpoint,
        sourceFingerprint,
        size,
        sha256,
      }) => ({
        id,
        filename,
        sourceEndpoint,
        sourceFingerprint,
        size,
        sha256,
      }),
    );

  return JSON.stringify({
    schemaVersion: SCHEMA_VERSION,
    product,
    assets: canonicalAssets,
  });
}

export function createManifestDigest(product, assets) {
  return createHash("sha256")
    .update(canonicalDigestInput(product, assets))
    .digest("hex");
}

export function createReleaseTag(now, digest) {
  if (!(now instanceof Date)) {
    throw new TypeError("now must be a valid Date instance");
  }
  let timestamp;
  try {
    timestamp = Date.prototype.getTime.call(now);
  } catch {
    throw new TypeError("now must be a valid Date instance");
  }
  if (Number.isNaN(timestamp)) {
    throw new TypeError("now must be a valid Date instance");
  }
  if (typeof digest !== "string" || !SHA256_PATTERN.test(digest)) {
    throw new Error("digest must be 64 lowercase hex characters");
  }
  const isoDate = Date.prototype.toISOString.call(now).slice(0, 10);
  return `${isoDate}-${digest.slice(0, 8)}`;
}
