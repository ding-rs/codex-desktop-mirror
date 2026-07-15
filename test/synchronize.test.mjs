import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  access,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import { createGitHubReleaseAdapter } from "../scripts/lib/github-releases.mjs";
import {
  createManifestDigest,
  createReleaseTag,
} from "../scripts/lib/snapshot.mjs";
import { synchronize } from "../scripts/lib/synchronize.mjs";
import { main, verifyWindowsSignature } from "../scripts/sync.mjs";

const EXPECTED_IDS = [
  "darwin-arm64-dmg",
  "darwin-x64-dmg",
  "win32-x64-msix",
  "win32-x64-installer",
];
const FILENAMES = {
  "darwin-arm64-dmg": "Codex-macOS-arm64.dmg",
  "darwin-x64-dmg": "Codex-macOS-x64.dmg",
  "win32-x64-msix": "Codex-Windows-x64.msix",
  "win32-x64-installer": "Codex-Windows-Installer.exe",
};
const NOW = new Date("2026-07-16T01:02:03.000Z");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function bytesFor(id, version = "old") {
  return Buffer.from(`${version}:${id}`);
}

function assetFor(id, version = "old") {
  const bytes = bytesFor(id, version);
  return {
    id,
    filename: FILENAMES[id],
    sourceEndpoint: `https://source.example/${id}`,
    sourceFingerprint: `${version}-fingerprint:${id}`,
    size: bytes.length,
    sha256: sha256(bytes),
  };
}

function matchingManifest() {
  const product = "codex-desktop";
  const generatedAt = "2026-07-15T01:02:03.000Z";
  const assets = EXPECTED_IDS.map((id) => assetFor(id));
  const manifestDigest = createManifestDigest(product, assets);
  const releaseTag = createReleaseTag(new Date(generatedAt), manifestDigest);
  return {
    schemaVersion: 1,
    product,
    generatedAt,
    releaseTag,
    manifestDigest,
    assets,
  };
}

function probes({ changedId, reverse = false, runtimeFields = false } = {}) {
  const values = EXPECTED_IDS.map((id) => ({
    id,
    filename: FILENAMES[id],
    sourceEndpoint: `https://source.example/${id}`,
    sourceFingerprint:
      id === changedId ? `new-fingerprint:${id}` : `old-fingerprint:${id}`,
    ...(runtimeFields
      ? {
          resolvedUrl: `https://signed.example/${id}?token=secret`,
          expectedSize: 123,
          path: "/untrusted/path",
          arbitraryRuntimeField: "must-not-survive",
        }
      : {}),
  }));
  return reverse ? values.reverse() : values;
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "codex-sync-test-"));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function stageBytes(destination, bytes) {
  await writeFile(destination, bytes, { flag: "wx" });
  return { size: bytes.length, sha256: sha256(bytes) };
}

function fixture(
  root,
  {
    previous = {
      tag: matchingManifest().releaseTag,
      manifest: matchingManifest(),
    },
    changedId,
    reverse = false,
    runtimeFields = false,
    probeOverride,
    stageFailure,
    createFailure,
    verifyFailure,
    publishFailure,
    cleanupFailure,
  } = {},
) {
  const events = [];
  const workDir = join(root, "work");
  const source = {
    async probe() {
      events.push("probe");
      return probeOverride ?? probes({ changedId, reverse, runtimeFields });
    },
    async stageChanged(probe, destination) {
      events.push(`stageChanged:${probe.id}`);
      if (stageFailure === probe.id) throw new Error("stage failed");
      return stageBytes(destination, bytesFor(probe.id, "new"));
    },
  };
  const releases = {
    async readLatestManifest() {
      events.push("readLatest");
      return previous;
    },
    async stagePrevious(tag, previousAsset, destination) {
      events.push(`stagePrevious:${previousAsset.id}`);
      assert.equal(tag, matchingManifest().releaseTag);
      return stageBytes(destination, bytesFor(previousAsset.id));
    },
    async writeMetadata(_workDir, manifest, staged) {
      events.push("writeMetadata");
      assert.equal(_workDir, workDir);
      assert.equal(staged.length, EXPECTED_IDS.length);
      await writeFile(
        join(workDir, "manifest.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
      await writeFile(join(workDir, "SHA256SUMS"), "fixture\n");
    },
    async createDraft() {
      events.push("createDraft");
      if (createFailure) {
        const error = new Error("draft creation failed");
        if (createFailure === "exists") error.draftCreated = true;
        throw error;
      }
    },
    async uploadAll() {
      events.push("uploadAll");
    },
    async verifyDraft() {
      events.push("verifyDraft");
      if (verifyFailure) throw new Error("draft verification failed");
    },
    async publishDraft() {
      events.push("publishDraft");
      if (publishFailure) {
        const error = new Error("publish failed");
        if (publishFailure === "published") error.releasePublished = true;
        if (publishFailure === "unknown") error.publishStateUnknown = true;
        throw error;
      }
    },
    async deleteDraft() {
      events.push("deleteDraft");
      if (cleanupFailure) throw new Error("cleanup failed");
    },
  };
  return {
    args: {
      product: "codex-desktop",
      expectedIds: EXPECTED_IDS,
      now: NOW,
      workDir,
      source,
      releases,
    },
    events,
    workDir,
  };
}

test("no-change exits before binary staging and release writes", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root);
    const result = await synchronize(args);
    assert.deepEqual(result, { status: "no-changes" });
    assert.deepEqual(events, ["readLatest", "probe"]);
  });
});

test("previous manifest top-level integrity is verified before probing", async () => {
  await withTempDir(async (root) => {
    const cases = [
      (previous) => {
        previous.manifest.product = "other-product";
      },
      (previous) => {
        previous.manifest.releaseTag = "2026-07-15-deadbeef";
      },
      (previous) => {
        previous.tag = "2026-07-15-deadbeef";
      },
      (previous) => {
        previous.manifest.generatedAt = "2026-07-15T01:02:03Z";
      },
      (previous) => {
        previous.manifest.manifestDigest = "0".repeat(64);
      },
      (previous) => {
        previous.manifest.releaseTag = "2026-07-15-deadbeef";
        previous.tag = "2026-07-15-deadbeef";
      },
    ];
    for (const mutate of cases) {
      const manifest = structuredClone(matchingManifest());
      const previous = { tag: manifest.releaseTag, manifest };
      mutate(previous);
      const setup = fixture(root, { previous });
      await assert.rejects(
        synchronize(setup.args),
        /product|releaseTag|generatedAt|manifestDigest|tag/i,
      );
      assert.deepEqual(setup.events, ["readLatest"]);
      await rm(setup.workDir, { recursive: true, force: true });
    }
  });
});

test("invalid synchronize inputs fail before mkdir, remote, or source I/O", async () => {
  await withTempDir(async (root) => {
    const cases = [
      { product: "" },
      { now: new Date(Number.NaN) },
      { expectedIds: [EXPECTED_IDS[0], EXPECTED_IDS[0]] },
      { expectedIds: ["", ...EXPECTED_IDS.slice(1)] },
      { workDir: 42 },
      { logger: null },
      { source: {} },
      { releases: {} },
    ];
    for (const [index, changes] of cases.entries()) {
      const workDir = join(root, `invalid-${index}`);
      const events = [];
      const base = fixture(root).args;
      const source = {
        probe: async () => events.push("probe"),
        stageChanged: async () => events.push("stageChanged"),
      };
      const releases = {
        readLatestManifest: async () => events.push("readLatest"),
        stagePrevious: async () => events.push("stagePrevious"),
        writeMetadata: async () => events.push("writeMetadata"),
        createDraft: async () => events.push("createDraft"),
        uploadAll: async () => events.push("uploadAll"),
        verifyDraft: async () => events.push("verifyDraft"),
        publishDraft: async () => events.push("publishDraft"),
        deleteDraft: async () => events.push("deleteDraft"),
      };
      await assert.rejects(
        synchronize({ ...base, workDir, source, releases, ...changes }),
        /product|now|expectedIds|workDir|logger|source|releases|method/i,
      );
      assert.deepEqual(events, []);
      await assert.rejects(access(workDir));
    }
  });
});

test("probe getters are read once into an immutable plain snapshot", async () => {
  await withTempDir(async (root) => {
    const reads = new Map();
    const probeOverride = probes().map((value) => {
      const result = {};
      for (const field of [
        "id",
        "filename",
        "sourceEndpoint",
        "sourceFingerprint",
        "resolvedUrl",
        "expectedSize",
      ]) {
        const key = `${value.id}:${field}`;
        Object.defineProperty(result, field, {
          enumerable: true,
          get() {
            reads.set(key, (reads.get(key) ?? 0) + 1);
            return value[field];
          },
        });
      }
      return result;
    });
    const setup = fixture(root, { previous: null, probeOverride });
    await synchronize(setup.args);
    assert.ok([...reads.values()].every((count) => count === 1));
    assert.equal(reads.size, EXPECTED_IDS.length * 6);
  });
});

test("first run stages every upstream asset then publishes", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, { previous: null });
    const result = await synchronize(args);
    assert.equal(result.status, "published");
    assert.deepEqual(events, [
      "readLatest",
      "probe",
      "stageChanged:darwin-arm64-dmg",
      "stageChanged:darwin-x64-dmg",
      "stageChanged:win32-x64-msix",
      "stageChanged:win32-x64-installer",
      "writeMetadata",
      "createDraft",
      "uploadAll",
      "verifyDraft",
      "publishDraft",
    ]);
  });
});

test("one changed asset reuses the previous release for the rest in probe order", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      reverse: true,
    });
    await synchronize(args);
    assert.deepEqual(events.slice(2, 6), [
      "stagePrevious:win32-x64-installer",
      "stagePrevious:win32-x64-msix",
      "stagePrevious:darwin-x64-dmg",
      "stageChanged:darwin-arm64-dmg",
    ]);
  });
});

test("workDir must be empty before any release or source call", async () => {
  await withTempDir(async (root) => {
    const setup = fixture(root);
    await import("node:fs/promises").then(({ mkdir }) =>
      mkdir(setup.workDir, { recursive: true }),
    );
    await writeFile(join(setup.workDir, "leftover"), "unsafe");
    await assert.rejects(synchronize(setup.args), /workDir.*empty|empty.*workDir/i);
    assert.deepEqual(setup.events, []);
  });
});

test("invalid probe set and unsafe filenames fail before binary or release writes", async () => {
  await withTempDir(async (root) => {
    for (const probeOverride of [
      probes().slice(1),
      probes().map((probe, index) =>
        index === 0 ? { ...probe, filename: "../escape.dmg" } : probe,
      ),
    ]) {
      const setup = fixture(root, { previous: null, probeOverride });
      await assert.rejects(synchronize(setup.args), /probe id|filename/i);
      assert.deepEqual(setup.events, ["readLatest", "probe"]);
      await rm(setup.workDir, { recursive: true, force: true });
    }
  });
});

test("stage failure happens before draft creation", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      previous: null,
      stageFailure: "darwin-x64-dmg",
    });
    await assert.rejects(synchronize(args), /stage failed/);
    assert.equal(events.includes("createDraft"), false);
    assert.equal(events.includes("deleteDraft"), false);
  });
});

test("synchronize independently hashes staged bytes instead of trusting adapter metadata", async () => {
  await withTempDir(async (root) => {
    const setup = fixture(root, { previous: null });
    const realStage = setup.args.source.stageChanged;
    setup.args.source.stageChanged = async (probe, destination) => {
      await realStage(probe, destination);
      return { size: 1, sha256: "f".repeat(64) };
    };
    let metadataStaged;
    const realWrite = setup.args.releases.writeMetadata;
    setup.args.releases.writeMetadata = async (workDir, manifest, staged) => {
      metadataStaged = structuredClone(staged);
      await realWrite(workDir, manifest, staged);
    };

    const result = await synchronize(setup.args);
    for (const asset of result.manifest.assets) {
      const bytes = bytesFor(asset.id, "new");
      assert.equal(asset.size, bytes.length);
      assert.equal(asset.sha256, sha256(bytes));
      const staged = metadataStaged.find((value) => value.id === asset.id);
      assert.equal(staged.size, bytes.length);
      assert.equal(staged.sha256, sha256(bytes));
    }
  });
});

test("missing or symlinked staged destinations fail before draft creation", async () => {
  await withTempDir(async (root) => {
    for (const mode of ["missing", "symlink"]) {
      const setup = fixture(root, { previous: null });
      const target = join(root, `${mode}-target`);
      await writeFile(target, "target");
      setup.args.source.stageChanged = async (probe, destination) => {
        setup.events.push(`stageChanged:${probe.id}`);
        if (mode === "symlink") await symlink(target, destination);
        return { size: 6, sha256: sha256("target") };
      };
      await assert.rejects(synchronize(setup.args), /regular file|symlink|missing|ENOENT/i);
      assert.equal(setup.events.includes("createDraft"), false);
      await rm(setup.workDir, { recursive: true, force: true });
    }
  });
});

test("draft verification failure deletes the draft and never publishes", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      verifyFailure: true,
    });
    await assert.rejects(synchronize(args), /draft verification failed/);
    assert.equal(events.at(-1), "deleteDraft");
    assert.equal(events.includes("publishDraft"), false);
  });
});

test("a definitely failed publish cleans up the still-draft release", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      publishFailure: true,
    });
    await assert.rejects(synchronize(args), /publish failed/);
    assert.deepEqual(events.slice(-2), ["publishDraft", "deleteDraft"]);
  });
});

test("a possibly published release is never deleted after ambiguous publish failure", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      publishFailure: "published",
    });
    await assert.rejects(synchronize(args), /publish failed/);
    assert.equal(events.includes("deleteDraft"), false);
  });
});

test("an unknown publish state is never cleaned up because the release may be published", async () => {
  await withTempDir(async (root) => {
    const { args, events } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      publishFailure: "unknown",
    });
    await assert.rejects(synchronize(args), /publish failed/);
    assert.deepEqual(events.slice(-1), ["publishDraft"]);
    assert.equal(events.includes("deleteDraft"), false);
  });
});

test("cleanup failure preserves both the operation and cleanup errors", async () => {
  await withTempDir(async (root) => {
    const { args } = fixture(root, {
      changedId: "darwin-arm64-dmg",
      verifyFailure: true,
      cleanupFailure: true,
    });
    await assert.rejects(synchronize(args), (error) => {
      assert.ok(error instanceof AggregateError);
      assert.equal(error.errors.length, 2);
      assert.match(error.errors[0].message, /verification/);
      assert.match(error.errors[1].message, /cleanup/);
      return true;
    });
  });
});

test("a create failure cleans up only when the adapter confirms a draft exists", async () => {
  await withTempDir(async (root) => {
    const absent = fixture(root, {
      previous: null,
      createFailure: "absent",
    });
    await assert.rejects(synchronize(absent.args), /creation failed/);
    assert.equal(absent.events.includes("deleteDraft"), false);

    await rm(absent.workDir, { recursive: true, force: true });
    const exists = fixture(root, { previous: null, createFailure: "exists" });
    await assert.rejects(synchronize(exists.args), /creation failed/);
    assert.equal(exists.events.at(-1), "deleteDraft");
  });
});

test("an already-published matching snapshot skips draft upload and returns published", async () => {
  await withTempDir(async (root) => {
    const setup = fixture(root, { previous: null });
    setup.args.releases.createDraft = async () => {
      setup.events.push("createDraft");
      return { alreadyPublished: true };
    };
    const result = await synchronize(setup.args);
    assert.equal(result.status, "published");
    assert.deepEqual(setup.events.slice(-2), ["writeMetadata", "createDraft"]);
    assert.equal(setup.events.includes("uploadAll"), false);
    assert.equal(setup.events.includes("deleteDraft"), false);
  });
});

test("manifest is stable, explicitly allowlisted, and strips every runtime field", async () => {
  await withTempDir(async (root) => {
    const { args } = fixture(root, {
      previous: null,
      reverse: true,
      runtimeFields: true,
    });
    const { manifest, tag } = await synchronize(args);
    assert.equal(manifest.releaseTag, tag);
    assert.equal(manifest.generatedAt, NOW.toISOString());
    assert.equal(manifest.schemaVersion, 1);
    assert.match(manifest.manifestDigest, /^[0-9a-f]{64}$/);
    assert.deepEqual(
      manifest.assets.map((asset) => asset.id),
      [...EXPECTED_IDS].sort(),
    );
    for (const asset of manifest.assets) {
      assert.deepEqual(Object.keys(asset), [
        "id",
        "filename",
        "sourceEndpoint",
        "sourceFingerprint",
        "size",
        "sha256",
      ]);
    }
    const serialized = JSON.stringify(manifest);
    assert.doesNotMatch(serialized, /resolvedUrl|expectedSize|path|arbitraryRuntimeField|secret/);
  });
});

function validManifest() {
  return matchingManifest();
}

function execError(stderr, code = 1) {
  return Object.assign(new Error("command failed and may contain token=secret"), {
    code,
    stderr,
    stdout: "",
  });
}

function fakeExec(handler) {
  const calls = [];
  const execFileImpl = async (file, args, options) => {
    calls.push({ file, args, options });
    return (await handler?.(file, args, options, calls.length)) ?? {
      stdout: "",
      stderr: "",
    };
  };
  return { calls, execFileImpl };
}

test("GitHub adapter rejects malformed repositories before invoking gh", () => {
  const { calls, execFileImpl } = fakeExec();
  for (const repo of ["owner", "/repo", "owner/", "owner/repo/extra", "-o/repo", "owner/../repo"])
    assert.throws(
      () => createGitHubReleaseAdapter({ repo, token: "token", execFileImpl }),
      /repository|repo/i,
    );
  assert.deepEqual(calls, []);
});

test("GitHub adapter treats only an explicit no-releases exit as first run", async () => {
  for (const [stderr, expected] of [
    ["no releases found", null],
    ["HTTP 500", "reject"],
  ]) {
    const fake = fakeExec(async () => {
      throw execError(stderr);
    });
    const adapter = createGitHubReleaseAdapter({
      repo: "ding-rs/codex-desktop-mirror",
      token: "top-secret-token",
      execFileImpl: fake.execFileImpl,
    });
    if (expected === null) assert.equal(await adapter.readLatestManifest(EXPECTED_IDS), null);
    else
      await assert.rejects(adapter.readLatestManifest(EXPECTED_IDS), (error) => {
        assert.doesNotMatch(error.stack, /top-secret-token|token=secret/);
        return true;
      });
  }
});

test("GitHub adapter reads latest tag and downloads exactly manifest.json", async () => {
  const fake = fakeExec(async (_file, args) => {
    if (args[1] === "view") return { stdout: JSON.stringify({ tagName: "old-tag" }), stderr: "" };
    if (args[1] === "download") {
      const output = args[args.indexOf("--output") + 1];
      await writeFile(output, `${JSON.stringify(validManifest())}\n`);
      return { stdout: "", stderr: "" };
    }
  });
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "top-secret-token",
    execFileImpl: fake.execFileImpl,
  });
  const latest = await adapter.readLatestManifest(EXPECTED_IDS);
  assert.equal(latest.tag, "old-tag");
  assert.deepEqual(latest.manifest, validManifest());
  assert.deepEqual(fake.calls[0].args, [
    "release", "view", "--repo", "ding-rs/codex-desktop-mirror", "--json", "tagName",
  ]);
  assert.equal(fake.calls[1].args[fake.calls[1].args.indexOf("--pattern") + 1], "manifest.json");
  assert.ok(fake.calls.every((call) => call.file === "gh"));
  assert.ok(fake.calls.every((call) => call.options.env.GH_TOKEN === "top-secret-token"));
  assert.doesNotMatch(JSON.stringify(fake.calls.map((call) => call.args)), /top-secret-token/);
});

test("stagePrevious verifies real size and SHA256 and removes mismatches", async () => {
  await withTempDir(async (root) => {
    const destination = join(root, "asset.bin");
    const fake = fakeExec(async (_file, args) => {
      await writeFile(args[args.indexOf("--output") + 1], "tampered");
      return { stdout: "", stderr: "" };
    });
    const adapter = createGitHubReleaseAdapter({
      repo: "ding-rs/codex-desktop-mirror",
      token: "token",
      execFileImpl: fake.execFileImpl,
    });
    await assert.rejects(
      adapter.stagePrevious("old-tag", assetFor(EXPECTED_IDS[0]), destination),
      /size|sha256|integrity/i,
    );
    await assert.rejects(access(destination));
  });
});

test("stagePrevious downloads one exact named asset and returns its verified hash", async () => {
  await withTempDir(async (root) => {
    const previousAsset = assetFor(EXPECTED_IDS[0]);
    const destination = join(root, previousAsset.filename);
    const fake = fakeExec(async (_file, args) => {
      await writeFile(args[args.indexOf("--output") + 1], bytesFor(previousAsset.id));
      return { stdout: "", stderr: "" };
    });
    const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
    assert.deepEqual(await adapter.stagePrevious("old-tag", previousAsset, destination), {
      size: previousAsset.size,
      sha256: previousAsset.sha256,
    });
    assert.equal(fake.calls[0].args[fake.calls[0].args.indexOf("--pattern") + 1], previousAsset.filename);
    assert.equal(fake.calls[0].args.includes("--clobber"), false);
  });
});

test("downloadExact preserves a concurrent destination occupant and cleans only its own temp", async () => {
  await withTempDir(async (root) => {
    const previousAsset = assetFor(EXPECTED_IDS[0]);
    const destination = join(root, previousAsset.filename);
    let downloadOutput;
    const fake = fakeExec(async (_file, args) => {
      downloadOutput = args[args.indexOf("--output") + 1];
      await writeFile(downloadOutput, bytesFor(previousAsset.id));
      await writeFile(destination, "concurrent-owner", {
        flag: downloadOutput === destination ? "w" : "wx",
      });
      return { stdout: "", stderr: "" };
    });
    const adapter = createGitHubReleaseAdapter({
      repo: "ding-rs/codex-desktop-mirror",
      token: "token",
      execFileImpl: fake.execFileImpl,
    });
    await assert.rejects(
      adapter.stagePrevious("old-tag", previousAsset, destination),
      /exist|destination|integrity|release/i,
    );
    assert.notEqual(downloadOutput, destination);
    assert.equal(await readFile(destination, "utf8"), "concurrent-owner");
  });
});

test("writeMetadata emits deterministic manifest JSON and sorted installer-only checksums", async () => {
  await withTempDir(async (root) => {
    const fake = fakeExec();
    const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
    const staged = EXPECTED_IDS.map((id) => ({ ...assetFor(id), path: join(root, FILENAMES[id]) })).reverse();
    for (const asset of staged) await writeFile(asset.path, bytesFor(asset.id));
    const manifest = { ...validManifest(), marker: "é" };
    await adapter.writeMetadata(root, manifest, staged);
    assert.equal(await readFile(join(root, "manifest.json"), "utf8"), `${JSON.stringify(manifest, null, 2)}\n`);
    assert.equal(
      await readFile(join(root, "SHA256SUMS"), "utf8"),
      [...staged]
        .sort((left, right) => (left.filename < right.filename ? -1 : left.filename > right.filename ? 1 : 0))
        .map((asset) => `${asset.sha256}  ${asset.filename}\n`)
        .join(""),
    );
  });
});

test("draft creation and upload use exact argv arrays without clobber or token arguments", async () => {
  await withTempDir(async (root) => {
    const fake = fakeExec();
    const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "top-secret-token", runToken: "run-a", execFileImpl: fake.execFileImpl });
    const staged = EXPECTED_IDS.map((id) => ({ ...assetFor(id), path: join(root, FILENAMES[id]) }));
    for (const asset of staged) await writeFile(asset.path, bytesFor(asset.id));
    await writeFile(join(root, "manifest.json"), "{}\n");
    await writeFile(join(root, "SHA256SUMS"), "sums\n");
    await adapter.createDraft("new-tag", validManifest());
    await adapter.uploadAll("new-tag", root, staged);
    assert.deepEqual(fake.calls[0].args, [
      "release",
      "create",
      "new-tag",
      "--repo",
      "ding-rs/codex-desktop-mirror",
      "--draft",
      "--latest=false",
      "--title",
      "new-tag",
      "--notes",
      "Automated mirror snapshot from the documented upstream source endpoints.\n\n<!-- ding-rs-mirror-owner:run-a -->",
    ]);
    assert.equal(fake.calls[1].args.includes("--clobber"), false);
    assert.deepEqual(fake.calls[1].args.slice(0, 3), ["release", "upload", "new-tag"]);
    assert.doesNotMatch(JSON.stringify(fake.calls.map((call) => call.args)), /top-secret-token/);
  });
});

test("a draft owned by run A is an ownership conflict for run B and is never deleted", async () => {
  let runABody;
  const runA = fakeExec(async (_file, args) => {
    if (args[1] === "create") {
      runABody = args[args.indexOf("--notes") + 1];
    }
    return { stdout: "", stderr: "" };
  });
  const adapterA = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token-a",
    runToken: "run-a",
    execFileImpl: runA.execFileImpl,
  });
  await adapterA.createDraft("new-tag", validManifest());
  assert.match(runABody, /run-a/);

  const runB = fakeExec(async (_file, args) => {
    if (args[1] === "create") throw execError("already exists");
    if (args[1] === "view") {
      return {
        stdout: JSON.stringify({
          tagName: "new-tag",
          isDraft: true,
          body: runABody,
        }),
        stderr: "",
      };
    }
    assert.fail(`run B must not invoke ${args.join(" ")}`);
  });
  const adapterB = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token-b",
    runToken: "run-b",
    execFileImpl: runB.execFileImpl,
  });
  await assert.rejects(
    adapterB.createDraft("new-tag", validManifest()),
    (error) => {
      assert.equal(error.ownershipConflict, true);
      assert.equal(Boolean(error.draftCreated), false);
      return true;
    },
  );
  assert.equal(runB.calls.some((entry) => entry.args[1] === "delete"), false);
});

test("deleteDraft refuses missing or mismatched ownership markers", async () => {
  for (const body of ["", "<!-- ding-rs-mirror-owner:other-run -->"]) {
    const fake = fakeExec(async () => ({
      stdout: JSON.stringify({ tagName: "new-tag", isDraft: true, body }),
      stderr: "",
    }));
    const adapter = createGitHubReleaseAdapter({
      repo: "ding-rs/codex-desktop-mirror",
      token: "token",
      runToken: "run-a",
      execFileImpl: fake.execFileImpl,
    });
    await assert.rejects(adapter.deleteDraft("new-tag"), /owner|ownership|marker/i);
    assert.equal(fake.calls.some((entry) => entry.args[1] === "delete"), false);
  }
});

test("deleteDraft removes only a draft carrying this run's exact marker", async () => {
  const marker = "<!-- ding-rs-mirror-owner:run-a -->";
  const fake = fakeExec(async (_file, args) =>
    args[1] === "view"
      ? {
          stdout: JSON.stringify({
            tagName: "new-tag",
            isDraft: true,
            body: marker,
          }),
          stderr: "",
        }
      : { stdout: "", stderr: "" },
  );
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    runToken: "run-a",
    execFileImpl: fake.execFileImpl,
  });
  await adapter.deleteDraft("new-tag");
  assert.ok(fake.calls[1].args.includes("--cleanup-tag"));
});

async function preparedDraft(root, assetChanges = (assets) => assets) {
  const staged = EXPECTED_IDS.map((id) => ({ ...assetFor(id), path: join(root, FILENAMES[id]) }));
  for (const asset of staged) await writeFile(asset.path, bytesFor(asset.id));
  await writeFile(join(root, "manifest.json"), "{}\n");
  await writeFile(join(root, "SHA256SUMS"), "sums\n");
  const expected = await Promise.all(
    [...staged.map((asset) => asset.path), join(root, "manifest.json"), join(root, "SHA256SUMS")].map(async (path) => ({
      name: basename(path),
      size: (await stat(path)).size,
    })),
  );
  return { staged, response: { tagName: "new-tag", isDraft: true, assets: assetChanges(expected) } };
}

test("verifyDraft accepts only an exact draft asset name and size set", async () => {
  await withTempDir(async (root) => {
    for (const mutate of [
      (assets) => assets,
      (assets) => assets.slice(1),
      (assets) => [...assets, { name: "extra.bin", size: 1 }],
      (assets) => assets.map((asset, index) => index === 0 ? { ...asset, size: asset.size + 1 } : asset),
    ]) {
      const { staged, response } = await preparedDraft(root, mutate);
      const fake = fakeExec(async () => ({ stdout: JSON.stringify(response), stderr: "" }));
      const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
      const operation = adapter.verifyDraft("new-tag", validManifest(), staged);
      if (response.assets.length === staged.length + 2 && response.assets.every((asset, index) => index === 0 ? asset.size === staged[0].size : true)) await operation;
      else await assert.rejects(operation, /draft|asset|size/i);
      await rm(join(root, "manifest.json"), { force: true });
      await rm(join(root, "SHA256SUMS"), { force: true });
      for (const asset of staged) await rm(asset.path, { force: true });
    }
  });
});

test("verifyDraft rejects a published release even when assets match", async () => {
  await withTempDir(async (root) => {
    const { staged, response } = await preparedDraft(root);
    response.isDraft = false;
    const fake = fakeExec(async () => ({ stdout: JSON.stringify(response), stderr: "" }));
    const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
    await assert.rejects(adapter.verifyDraft("new-tag", validManifest(), staged), /draft/i);
  });
});

test("publishDraft reconciles an ambiguous edit when target is latest or still draft", async () => {
  for (const scenario of ["published-latest", "still-draft"]) {
    let call = 0;
    const fake = fakeExec(async (_file, args) => {
      call += 1;
      if (call === 1) throw execError("network unavailable");
      if (call === 2)
        return {
          stdout: JSON.stringify({
            tagName: "new-tag",
            isDraft: scenario === "still-draft",
          }),
          stderr: "",
        };
      assert.equal(args[2], "--repo");
      return {
        stdout: JSON.stringify({ tagName: "new-tag" }),
        stderr: "",
      };
    });
    const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
    if (scenario === "published-latest") await adapter.publishDraft("new-tag");
    else
      await assert.rejects(adapter.publishDraft("new-tag"), (error) => {
        assert.equal(Boolean(error.releasePublished), false);
        return true;
      });
  }
});

test("publishDraft marks state unknown when edit and first reconciliation both fail", async () => {
  let call = 0;
  const fake = fakeExec(async () => {
    call += 1;
    if (call === 1) throw execError("publish network unavailable");
    throw execError("reconciliation network unavailable");
  });
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    execFileImpl: fake.execFileImpl,
  });

  await assert.rejects(adapter.publishDraft("new-tag"), (error) => {
    assert.equal(error.publishStateUnknown, true);
    assert.match(error.message, /release edit failed/i);
    return true;
  });
  assert.equal(fake.calls.length, 2);
  assert.equal(fake.calls.some((entry) => entry.args[1] === "delete"), false);
});

test("publishDraft post-verifies even a successful edit and rejects a still-draft release", async () => {
  let call = 0;
  const fake = fakeExec(async (_file, args) => {
    call += 1;
    if (call === 1) {
      assert.equal(args[1], "edit");
      return { stdout: "", stderr: "" };
    }
    assert.equal(args[1], "view");
    return {
      stdout: JSON.stringify({
        tagName: "new-tag",
        isDraft: true,
        body: "<!-- ding-rs-mirror-owner:run-a -->",
      }),
      stderr: "",
    };
  });
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    runToken: "run-a",
    execFileImpl: fake.execFileImpl,
  });
  await assert.rejects(adapter.publishDraft("new-tag"), /draft|publish/i);
  assert.equal(fake.calls.length, 2);
});

test("publishDraft recovers a non-draft target that was not marked latest and post-verifies", async () => {
  let tagViews = 0;
  let latestViews = 0;
  const fake = fakeExec(async (_file, args) => {
    if (args[1] === "edit") return { stdout: "", stderr: "" };
    if (args[1] === "view" && args[2] === "new-tag") {
      tagViews += 1;
      return {
        stdout: JSON.stringify({
          tagName: "new-tag",
          isDraft: false,
          body: "<!-- ding-rs-mirror-owner:run-a -->",
        }),
        stderr: "",
      };
    }
    latestViews += 1;
    return {
      stdout: JSON.stringify({
        tagName: latestViews === 1 ? "old-tag" : "new-tag",
      }),
      stderr: "",
    };
  });
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    runToken: "run-a",
    execFileImpl: fake.execFileImpl,
  });
  await adapter.publishDraft("new-tag");
  assert.equal(fake.calls.filter((entry) => entry.args[1] === "edit").length, 2);
  assert.equal(tagViews, 2);
  assert.equal(latestViews, 2);
});

test("publishDraft marks state unknown when post-verification fails after edit exit zero", async () => {
  let call = 0;
  const fake = fakeExec(async () => {
    call += 1;
    if (call === 1) return { stdout: "", stderr: "" };
    throw execError("post-verify network unavailable");
  });
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    runToken: "run-a",
    execFileImpl: fake.execFileImpl,
  });
  await assert.rejects(adapter.publishDraft("new-tag"), (error) => {
    assert.equal(error.publishStateUnknown, true);
    return true;
  });
});

test("createDraft recovers a matching pre-existing published snapshot and rejects mismatches", async () => {
  await withTempDir(async (root) => {
    for (const mode of [
      "match",
      "digest-mismatch",
      "assets-mismatch",
      "generated-missing",
      "generated-noncanonical",
      "generated-wrong-date",
    ]) {
      const mismatch = mode !== "match";
      const workDir = join(root, mode);
      await import("node:fs/promises").then(({ mkdir }) =>
        mkdir(workDir, { recursive: true }),
      );
      const staged = EXPECTED_IDS.map((id) => ({
        ...assetFor(id),
        path: join(workDir, FILENAMES[id]),
      }));
      for (const asset of staged) await writeFile(asset.path, bytesFor(asset.id));
      const manifest = matchingManifest();
      const tag = manifest.releaseTag;
      await writeFile(join(workDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
      await writeFile(join(workDir, "SHA256SUMS"), "checksums\n");
      const expectedAssets = await Promise.all(
        [...staged.map((asset) => asset.path), join(workDir, "manifest.json"), join(workDir, "SHA256SUMS")].map(async (path) => ({
          name: basename(path),
          size: (await stat(path)).size,
        })),
      );
      let tagViews = 0;
      const fake = fakeExec(async (_file, args) => {
        if (args[1] === "create") throw execError("already exists");
        if (args[1] === "download") {
          const output = args[args.indexOf("--output") + 1];
          let remoteManifest = manifest;
          if (mode === "digest-mismatch") {
            remoteManifest = { ...manifest, manifestDigest: "f".repeat(64) };
          } else if (mode === "assets-mismatch") {
            remoteManifest = {
              ...manifest,
              assets: manifest.assets.map((asset, index) =>
                index === 0
                  ? { ...asset, sha256: "f".repeat(64) }
                  : asset,
              ),
            };
          } else if (mode === "generated-missing") {
            remoteManifest = { ...manifest };
            delete remoteManifest.generatedAt;
          } else if (mode === "generated-noncanonical") {
            remoteManifest = {
              ...manifest,
              generatedAt: "2026-07-15T01:02:03Z",
            };
          } else if (mode === "generated-wrong-date") {
            remoteManifest = {
              ...manifest,
              generatedAt: "2026-07-14T01:02:03.000Z",
            };
          }
          await writeFile(output, `${JSON.stringify(remoteManifest)}\n`);
          return { stdout: "", stderr: "" };
        }
        if (args[1] === "edit") return { stdout: "", stderr: "" };
        if (args[1] === "view" && args[2] === tag) {
          tagViews += 1;
          return {
            stdout: JSON.stringify({
              tagName: tag,
              isDraft: false,
              body: "",
              assets: expectedAssets,
            }),
            stderr: "",
          };
        }
        return {
          stdout: JSON.stringify({ tagName: tag }),
          stderr: "",
        };
      });
      const adapter = createGitHubReleaseAdapter({
        repo: "ding-rs/codex-desktop-mirror",
        token: "token",
        runToken: "run-a",
        execFileImpl: fake.execFileImpl,
      });
      const operation = adapter.createDraft(
        tag,
        manifest,
        workDir,
        staged,
      );
      if (mismatch) {
        await assert.rejects(operation, (error) => {
          assert.equal(error.releasePublished, true);
          return true;
        });
        assert.equal(fake.calls.some((entry) => entry.args[1] === "delete"), false);
      } else {
        assert.deepEqual(await operation, { alreadyPublished: true });
        assert.ok(tagViews >= 2);
      }
    }
  });
});

test("deleteDraft refuses to delete a non-draft release", async () => {
  const fake = fakeExec(async () => ({ stdout: JSON.stringify({ tagName: "new-tag", isDraft: false }), stderr: "" }));
  const adapter = createGitHubReleaseAdapter({ repo: "ding-rs/codex-desktop-mirror", token: "token", execFileImpl: fake.execFileImpl });
  await assert.rejects(adapter.deleteDraft("new-tag"), /refus|non-draft|published/i);
  assert.equal(fake.calls.some((call) => call.args[1] === "delete"), false);
});

test("deleteDraft uses cleanup-tag and yes after confirming the release is a draft", async () => {
  const fake = fakeExec(async (_file, args) =>
    args[1] === "view"
      ? {
          stdout: JSON.stringify({
            tagName: "new-tag",
            isDraft: true,
            body: "<!-- ding-rs-mirror-owner:run-a -->",
          }),
          stderr: "",
        }
      : { stdout: "", stderr: "" },
  );
  const adapter = createGitHubReleaseAdapter({
    repo: "ding-rs/codex-desktop-mirror",
    token: "token",
    runToken: "run-a",
    execFileImpl: fake.execFileImpl,
  });
  await adapter.deleteDraft("new-tag");
  assert.deepEqual(fake.calls[1].args, [
    "release", "delete", "new-tag", "--repo", "ding-rs/codex-desktop-mirror", "--cleanup-tag", "--yes",
  ]);
});

test("verifyWindowsSignature invokes signtool with an argv array and sanitizes failures", async () => {
  const calls = [];
  await verifyWindowsSignature("C:\\safe path\\Codex.msix", {
    execFileImpl: async (file, args) => calls.push({ file, args }),
  });
  assert.deepEqual(calls, [{
    file: "signtool",
    args: ["verify", "/pa", "/all", "C:\\safe path\\Codex.msix"],
  }]);

  await assert.rejects(
    verifyWindowsSignature("C:\\safe\\Codex.msix", {
      execFileImpl: async () => {
        throw new Error("signtool leaked token=secret");
      },
    }),
    (error) => {
      assert.match(error.message, /signature verification failed/i);
      assert.doesNotMatch(error.stack, /token=secret/);
      return true;
    },
  );
});

test("probe-only accepts pnpm's separator, emits only safe fields, and never invokes executables", async () => {
  const output = [];
  let executableCalls = 0;
  const fetchImpl = async (url, init = {}) => {
    const requestUrl = String(url);
    if (requestUrl.includes("msft-store.tplant.com.au")) {
      const response = new Response(
        JSON.stringify([
          {
            packagemoniker: "OpenAI.Codex_1.2.3.0_x64__test",
            packagefilename: "OpenAI.Codex_1.2.3.0_x64.Msix",
            packagedownloadurl:
              "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix?token=signed-secret",
            packagefilesize: 123,
          },
        ]),
        { status: 200 },
      );
      Object.defineProperty(response, "url", { value: requestUrl });
      return response;
    }
    assert.equal(init.method, "HEAD");
    const response = new Response(null, {
      status: 200,
      headers: requestUrl.includes("get.microsoft.com")
        ? { "content-length": "103" }
        : { etag: `"etag-${requestUrl.includes("x64") ? "x64" : "arm64"}"`, "content-length": "102" },
    });
    Object.defineProperty(response, "url", { value: requestUrl });
    return response;
  };

  const result = await main({
    argv: ["--", "--probe-only"],
    env: {},
    fetchImpl,
    execFileImpl: async () => {
      executableCalls += 1;
      throw new Error("must not invoke gh or signtool");
    },
    stdout: (line) => output.push(line),
    stderr: () => assert.fail("probe-only must not emit phase logs"),
  });

  assert.equal(result.status, "probe-only");
  assert.equal(executableCalls, 0);
  assert.equal(output.length, 1);
  const serialized = output[0];
  const values = JSON.parse(serialized);
  assert.equal(values.length, 4);
  assert.ok(values.every((value) => Object.hasOwn(value, "sourceFingerprint")));
  assert.doesNotMatch(serialized, /resolvedUrl|signed-secret|packagedownloadurl/i);
});
