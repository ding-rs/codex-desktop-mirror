import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  MAX_ASSET_SIZE,
  SCHEMA_VERSION,
  assertPreviousManifest,
  assertStagedAssets,
  buildSyncPlan,
  canonicalDigestInput,
  createManifestDigest,
  createReleaseTag,
} from "../scripts/lib/snapshot.mjs";

const EXPECTED_IDS = [
  "darwin-arm64-dmg",
  "darwin-x64-dmg",
  "win32-x64-msix",
  "win32-x64-installer",
];

const FINGERPRINTS = Object.fromEntries(
  EXPECTED_IDS.map((id, index) => [id, `fingerprint-${index + 1}`]),
);

function makeProbes() {
  return EXPECTED_IDS.map((id) => ({
    id,
    sourceFingerprint: FINGERPRINTS[id],
  }));
}

function makeAssets() {
  return EXPECTED_IDS.map((id, index) => ({
    id,
    filename: `${id}.bin`,
    sourceEndpoint: `https://example.test/${id}`,
    sourceFingerprint: FINGERPRINTS[id],
    size: 1000 + index,
    sha256: String(index + 1).repeat(64),
  }));
}

function makeManifest() {
  return {
    schemaVersion: SCHEMA_VERSION,
    product: "Codex Desktop",
    assets: makeAssets(),
  };
}

function replaceAsset(assets, id, changes) {
  return assets.map((asset) =>
    asset.id === id ? { ...asset, ...changes } : asset,
  );
}

test("SCHEMA_VERSION is 1", () => {
  assert.equal(SCHEMA_VERSION, 1);
});

test("MAX_ASSET_SIZE is the shared exclusive 2 GiB limit", () => {
  assert.equal(MAX_ASSET_SIZE, 2 * 1024 ** 3);
});

test("first run marks every probe changed in probe order", () => {
  const probes = makeProbes();

  assert.deepEqual(buildSyncPlan(null, probes, EXPECTED_IDS), {
    hasChanges: true,
    changedIds: EXPECTED_IDS,
    unchangedIds: [],
  });
});

test("matching source fingerprints mark every probe unchanged", () => {
  assert.deepEqual(buildSyncPlan(makeManifest(), makeProbes(), EXPECTED_IDS), {
    hasChanges: false,
    changedIds: [],
    unchangedIds: EXPECTED_IDS,
  });
});

test("one changed source fingerprint changes only that asset", () => {
  const probes = replaceAsset(makeProbes(), "darwin-arm64-dmg", {
    sourceFingerprint: "new-arm64-fingerprint",
  });

  assert.deepEqual(buildSyncPlan(makeManifest(), probes, EXPECTED_IDS), {
    hasChanges: true,
    changedIds: ["darwin-arm64-dmg"],
    unchangedIds: [
      "darwin-x64-dmg",
      "win32-x64-msix",
      "win32-x64-installer",
    ],
  });
});

test("sync plan preserves probe order", () => {
  const probes = makeProbes().reverse();
  const manifest = makeManifest();
  manifest.assets = replaceAsset(manifest.assets, "darwin-arm64-dmg", {
    sourceFingerprint: "old-arm64-fingerprint",
  });

  assert.deepEqual(buildSyncPlan(manifest, probes, EXPECTED_IDS), {
    hasChanges: true,
    changedIds: ["darwin-arm64-dmg"],
    unchangedIds: [
      "win32-x64-installer",
      "win32-x64-msix",
      "darwin-x64-dmg",
    ],
  });
});

test("canonical manifest digest is deterministic and excludes runtime fields", () => {
  const assets = makeAssets().map((asset, index) => ({
    ...asset,
    resolvedUrl: `https://signed.example.test/${index}`,
    localPath: `/tmp/${asset.filename}`,
  }));
  const reversedAssets = [...assets].reverse().map((asset) => ({
    ...asset,
    resolvedUrl: "https://different-signed-url.example.test",
    localPath: "/different/runtime/path",
  }));

  const input = canonicalDigestInput("Codex Desktop", assets);
  assert.equal(input, canonicalDigestInput("Codex Desktop", reversedAssets));
  assert.deepEqual(JSON.parse(input), {
    schemaVersion: 1,
    product: "Codex Desktop",
    assets: [...makeAssets()]
      .sort((left, right) => left.id.localeCompare(right.id))
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
      ),
  });

  const expectedDigest = createHash("sha256").update(input).digest("hex");
  assert.equal(createManifestDigest("Codex Desktop", assets), expectedDigest);
  assert.equal(
    createManifestDigest("Codex Desktop", assets),
    createManifestDigest("Codex Desktop", reversedAssets),
  );
  assert.match(expectedDigest, /^[0-9a-f]{64}$/);
});

test("canonical digest sorts ids by deterministic code-unit order", () => {
  const assets = ["é", "a", "_", "Z", "ä", "0", "-"].map(
    (id, index) => ({
      id,
      filename: `asset-${index}.bin`,
      sourceEndpoint: `https://example.test/${index}`,
      sourceFingerprint: `fingerprint-${index}`,
      size: index + 1,
      sha256: "a".repeat(64),
    }),
  );

  const canonicalIds = JSON.parse(
    canonicalDigestInput("Codex Desktop", assets),
  ).assets.map((asset) => asset.id);

  assert.deepEqual(canonicalIds, ["-", "0", "Z", "_", "a", "ä", "é"]);
});

test("release tag uses UTC date and first eight digest characters", () => {
  assert.equal(
    createReleaseTag(
      new Date("2026-07-15T12:00:00Z"),
      `abcdef01${"2".repeat(56)}`,
    ),
    "2026-07-15-abcdef01",
  );
});

test("release tag rejects values that are not valid Date instances", () => {
  for (const now of [
    new Date(Number.NaN),
    "2026-07-15T12:00:00Z",
    { toISOString: () => "2026-07-15T12:00:00.000Z" },
  ]) {
    assert.throws(
      () => createReleaseTag(now, "a".repeat(64)),
      /now.*valid Date|valid Date.*now/,
    );
  }
});

test("release tag rejects digests that are not 64 lowercase hex characters", () => {
  for (const digest of ["a".repeat(63), "A".repeat(64), "g".repeat(64)]) {
    assert.throws(
      () => createReleaseTag(new Date("2026-07-15T12:00:00Z"), digest),
      /digest.*64.*lowercase hex/,
    );
  }
});

test("release tag uses intrinsic Date operations instead of instance overrides", () => {
  const now = new Date("2026-07-15T12:00:00Z");
  now.getTime = () => Number.NaN;
  now.toISOString = () => "1999-01-01T00:00:00.000Z";

  assert.equal(
    createReleaseTag(now, "a".repeat(64)),
    "2026-07-15-aaaaaaaa",
  );
});

test("previous manifest accepts null and a valid manifest", () => {
  assert.doesNotThrow(() => assertPreviousManifest(null, EXPECTED_IDS));
  assert.doesNotThrow(() =>
    assertPreviousManifest(makeManifest(), EXPECTED_IDS),
  );
});

test("previous manifest rejects an unsupported schema version", () => {
  assert.throws(
    () =>
      assertPreviousManifest(
        { ...makeManifest(), schemaVersion: 2 },
        EXPECTED_IDS,
      ),
    /schemaVersion/,
  );
});

test("previous manifest rejects a wrong or duplicate asset id set", () => {
  const missing = makeManifest();
  missing.assets = missing.assets.slice(1);
  assert.throws(
    () => assertPreviousManifest(missing, EXPECTED_IDS),
    /asset id/i,
  );

  const duplicate = makeManifest();
  duplicate.assets = [duplicate.assets[0], ...duplicate.assets.slice(0, -1)];
  assert.throws(
    () => assertPreviousManifest(duplicate, EXPECTED_IDS),
    /duplicate.*id|asset id/i,
  );
});

test("previous manifest rejects a missing sourceFingerprint", () => {
  const manifest = makeManifest();
  delete manifest.assets[0].sourceFingerprint;

  assert.throws(
    () => assertPreviousManifest(manifest, EXPECTED_IDS),
    /darwin-arm64-dmg.*sourceFingerprint|sourceFingerprint.*darwin-arm64-dmg/,
  );
});

test("previous manifest rejects missing, empty, and non-string sourceEndpoint", () => {
  const missing = makeManifest();
  delete missing.assets[0].sourceEndpoint;

  for (const manifest of [
    missing,
    {
      ...makeManifest(),
      assets: replaceAsset(makeAssets(), "darwin-arm64-dmg", {
        sourceEndpoint: "",
      }),
    },
    {
      ...makeManifest(),
      assets: replaceAsset(makeAssets(), "darwin-arm64-dmg", {
        sourceEndpoint: 42,
      }),
    },
  ]) {
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /darwin-arm64-dmg.*sourceEndpoint|sourceEndpoint.*darwin-arm64-dmg/,
    );
  }
});

test("previous manifest rejects missing, empty, and duplicate filenames", () => {
  const missing = makeManifest();
  delete missing.assets[0].filename;
  assert.throws(
    () => assertPreviousManifest(missing, EXPECTED_IDS),
    /darwin-arm64-dmg.*filename|filename.*darwin-arm64-dmg/,
  );

  const empty = makeManifest();
  empty.assets[0].filename = "";
  assert.throws(
    () => assertPreviousManifest(empty, EXPECTED_IDS),
    /darwin-arm64-dmg.*filename|filename.*darwin-arm64-dmg/,
  );

  const duplicate = makeManifest();
  duplicate.assets[1].filename = duplicate.assets[0].filename;
  assert.throws(
    () => assertPreviousManifest(duplicate, EXPECTED_IDS),
    /duplicate.*filename|filename.*unique/i,
  );
});

test("previous and staged assets reject unsafe filenames", () => {
  for (const filename of [
    "nested/file.dmg",
    "/absolute/file.dmg",
    "nested\\file.dmg",
    "bad\0name.dmg",
    "   ",
    " file.dmg",
    "file.dmg ",
    ".",
    "..",
  ]) {
    const manifest = makeManifest();
    manifest.assets[0].filename = filename;
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /darwin-arm64-dmg.*filename|filename.*darwin-arm64-dmg/,
    );

    const stagedAssets = makeAssets();
    stagedAssets[0].filename = filename;
    assert.throws(
      () => assertStagedAssets(stagedAssets, EXPECTED_IDS),
      /darwin-arm64-dmg.*filename|filename.*darwin-arm64-dmg/,
    );
  }
});

test("previous manifest rejects non-positive and non-safe-integer sizes", () => {
  for (const size of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const manifest = makeManifest();
    manifest.assets[0].size = size;
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /darwin-arm64-dmg.*size|size.*darwin-arm64-dmg/,
    );
  }
});

test("previous manifest rejects files at or above 2 GiB", () => {
  for (const size of [2 * 1024 ** 3, 2 * 1024 ** 3 + 1]) {
    const manifest = makeManifest();
    manifest.assets[0].size = size;
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /2 GiB/,
    );
  }
});

test("previous manifest rejects SHA256 values that are not lowercase hex", () => {
  for (const sha256 of ["a".repeat(63), "A".repeat(64), "g".repeat(64)]) {
    const manifest = makeManifest();
    manifest.assets[0].sha256 = sha256;
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /darwin-arm64-dmg.*sha256|sha256.*darwin-arm64-dmg/i,
    );
  }
});

test("previous and staged assets reject non-string SHA256 values explicitly", () => {
  for (const sha256 of [
    { toString: () => "a".repeat(64) },
    123,
    null,
    Symbol("sha256"),
  ]) {
    const manifest = makeManifest();
    manifest.assets[0].sha256 = sha256;
    assert.throws(
      () => assertPreviousManifest(manifest, EXPECTED_IDS),
      /darwin-arm64-dmg.*sha256.*string|sha256.*string.*darwin-arm64-dmg/i,
    );

    const stagedAssets = makeAssets();
    stagedAssets[0].sha256 = sha256;
    assert.throws(
      () => assertStagedAssets(stagedAssets, EXPECTED_IDS),
      /darwin-arm64-dmg.*sha256.*string|sha256.*string.*darwin-arm64-dmg/i,
    );
  }
});

test("staged assets accept an exact unique valid set", () => {
  assert.doesNotThrow(() => assertStagedAssets(makeAssets(), EXPECTED_IDS));
});

test("staged assets reject missing, extra, and duplicate ids", () => {
  assert.throws(
    () => assertStagedAssets(makeAssets().slice(1), EXPECTED_IDS),
    /asset id/i,
  );
  assert.throws(
    () =>
      assertStagedAssets(
        [...makeAssets(), { ...makeAssets()[0], id: "extra-id" }],
        EXPECTED_IDS,
      ),
    /asset id/i,
  );
  const duplicate = makeAssets();
  duplicate[3].id = duplicate[0].id;
  assert.throws(
    () => assertStagedAssets(duplicate, EXPECTED_IDS),
    /duplicate.*id|asset id/i,
  );
});

test("staged assets reject duplicate filenames", () => {
  const assets = makeAssets();
  assets[1].filename = assets[0].filename;

  assert.throws(
    () => assertStagedAssets(assets, EXPECTED_IDS),
    /duplicate.*filename|filename.*unique/i,
  );
});

test("staged assets reject invalid and non-positive sizes", () => {
  for (const size of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1000"]) {
    const assets = makeAssets();
    assets[0].size = size;
    assert.throws(
      () => assertStagedAssets(assets, EXPECTED_IDS),
      /darwin-arm64-dmg.*size|size.*darwin-arm64-dmg/,
    );
  }
});

test("staged assets reject files at or above 2 GiB", () => {
  for (const size of [2 * 1024 ** 3, 2 * 1024 ** 3 + 1]) {
    const assets = makeAssets();
    assets[0].size = size;
    assert.throws(() => assertStagedAssets(assets, EXPECTED_IDS), /2 GiB/);
  }
});

test("staged assets reject invalid SHA256 values", () => {
  const assets = makeAssets();
  assets[0].sha256 = "A".repeat(64);

  assert.throws(
    () => assertStagedAssets(assets, EXPECTED_IDS),
    /darwin-arm64-dmg.*sha256|sha256.*darwin-arm64-dmg/i,
  );
});

test("probe validation rejects missing, extra, and duplicate logical ids", () => {
  assert.throws(
    () => buildSyncPlan(null, makeProbes().slice(1), EXPECTED_IDS),
    /probe id/i,
  );
  assert.throws(
    () =>
      buildSyncPlan(
        null,
        [...makeProbes(), { id: "extra-id", sourceFingerprint: "extra" }],
        EXPECTED_IDS,
      ),
    /probe id/i,
  );
  const duplicate = makeProbes();
  duplicate[3].id = duplicate[0].id;
  assert.throws(
    () => buildSyncPlan(null, duplicate, EXPECTED_IDS),
    /duplicate.*probe.*id|probe id/i,
  );
});

test("expectedIds rejects malformed and sparse logical ids", () => {
  const sparseExpectedIds = new Array(1);
  for (const expectedIds of [
    [undefined],
    [""],
    ["   "],
    [42],
    [{}],
    sparseExpectedIds,
  ]) {
    assert.throws(
      () =>
        buildSyncPlan(
          null,
          [{ id: expectedIds[0], sourceFingerprint: "fingerprint" }],
          expectedIds,
        ),
      /expectedIds.*logical ID/i,
    );
  }
});

test("probe validation rejects missing, empty, and non-string source fingerprints", () => {
  const missing = makeProbes();
  delete missing[0].sourceFingerprint;

  for (const probes of [
    missing,
    replaceAsset(makeProbes(), "darwin-arm64-dmg", {
      sourceFingerprint: "",
    }),
    replaceAsset(makeProbes(), "darwin-arm64-dmg", {
      sourceFingerprint: 42,
    }),
  ]) {
    assert.throws(
      () => buildSyncPlan(null, probes, EXPECTED_IDS),
      /darwin-arm64-dmg.*sourceFingerprint|sourceFingerprint.*darwin-arm64-dmg/,
    );
  }
});

test("sync planning and canonical digest do not mutate frozen inputs", () => {
  const expectedIds = Object.freeze([...EXPECTED_IDS]);
  const probes = Object.freeze(makeProbes().map((probe) => Object.freeze(probe)));
  const manifestAssets = Object.freeze(
    makeAssets().map((asset) => Object.freeze(asset)),
  );
  const manifest = Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    product: "Codex Desktop",
    assets: manifestAssets,
  });

  assert.deepEqual(buildSyncPlan(manifest, probes, expectedIds), {
    hasChanges: false,
    changedIds: [],
    unchangedIds: EXPECTED_IDS,
  });

  const digestAssets = Object.freeze(
    [...makeAssets()].reverse().map((asset) => Object.freeze(asset)),
  );
  assert.doesNotThrow(() => canonicalDigestInput("Codex Desktop", digestAssets));
});
