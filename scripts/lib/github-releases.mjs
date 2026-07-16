import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  link,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import {
  assertPublishedManifestEnvelope,
  assertPreviousManifest,
} from "./snapshot.mjs";

const REPOSITORY_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const TAG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const NO_RELEASES_PATTERN = /no releases found/i;
const RELEASE_NOT_FOUND_PATTERN = /^\s*release not found\s*$/i;
const RUN_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function assertRepository(repo) {
  if (typeof repo !== "string" || !REPOSITORY_PATTERN.test(repo)) {
    throw new Error("GitHub repository must be a safe owner/name value");
  }
}

function assertTag(tag) {
  if (typeof tag !== "string" || !TAG_PATTERN.test(tag)) {
    throw new Error("release tag is invalid");
  }
}

function assertExactAssetName(name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    basename(name) !== name ||
    /[?*[\]{}\\\0]/.test(name)
  ) {
    throw new Error("release asset name must be an exact safe basename");
  }
}

function codeUnitCompare(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function parseJson(stdout, label) {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`GitHub CLI returned invalid JSON for ${label}`);
  }
}

function commandError(args, error) {
  const operation = args.slice(0, 2).join(" ");
  const result = new Error(`GitHub CLI ${operation} failed`);
  const exitCode = Number(error?.code);
  if (Number.isFinite(exitCode)) result.exitCode = exitCode;
  const stderr = typeof error?.stderr === "string" ? error.stderr : "";
  result.noReleases = exitCode === 1 && NO_RELEASES_PATTERN.test(stderr);
  result.releaseNotFound =
    exitCode === 1 && RELEASE_NOT_FOUND_PATTERN.test(stderr);
  return result;
}

async function hashFile(path) {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    size += chunk.length;
    hash.update(chunk);
  }
  return { size, sha256: hash.digest("hex") };
}

export function createGitHubReleaseAdapter({
  repo,
  token,
  execFileImpl,
  runToken = randomUUID(),
}) {
  assertRepository(repo);
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GitHub token is required");
  }
  if (typeof execFileImpl !== "function") {
    throw new TypeError("execFileImpl must be a function");
  }
  if (typeof runToken !== "string" || !RUN_TOKEN_PATTERN.test(runToken)) {
    throw new Error("run ownership token contains unsafe characters");
  }

  const environment = { ...process.env, GH_TOKEN: token };
  const ownershipMarker = `<!-- ding-rs-mirror-owner:${runToken} -->`;
  const releaseNotes =
    "Automated mirror snapshot from the documented upstream source endpoints.\n\n" +
    ownershipMarker;

  async function run(args) {
    try {
      const result = await execFileImpl("gh", args, {
        env: environment,
        windowsHide: true,
        maxBuffer: 4 * 1024 ** 2,
      });
      return {
        stdout: String(result?.stdout ?? ""),
        stderr: String(result?.stderr ?? ""),
      };
    } catch (error) {
      throw commandError(args, error);
    }
  }

  async function viewTag(tag, includeAssets = false) {
    assertTag(tag);
    const { stdout } = await run([
      "release",
      "view",
      tag,
      "--repo",
      repo,
      "--json",
      includeAssets ? "tagName,isDraft,body,assets" : "tagName,isDraft,body",
    ]);
    const value = parseJson(stdout, "release state");
    if (value?.tagName !== tag || typeof value?.isDraft !== "boolean") {
      throw new Error("GitHub release state is incomplete or mismatched");
    }
    return { ...value, body: typeof value.body === "string" ? value.body : "" };
  }

  async function viewLatestTag() {
    const { stdout } = await run([
      "release",
      "view",
      "--repo",
      repo,
      "--json",
      "tagName",
    ]);
    const value = parseJson(stdout, "latest release");
    if (typeof value?.tagName !== "string" || value.tagName.length === 0) {
      throw new Error("GitHub latest release tag is missing");
    }
    assertTag(value.tagName);
    return value.tagName;
  }

  async function downloadExact(
    tag,
    assetName,
    destination,
    validateTemporary,
  ) {
    assertTag(tag);
    assertExactAssetName(assetName);
    const directory = await mkdtemp(
      join(dirname(destination), ".gh-release-download-"),
    );
    const temporary = join(directory, assetName);
    try {
      await run([
        "release",
        "download",
        tag,
        "--repo",
        repo,
        "--pattern",
        assetName,
        "--output",
        temporary,
      ]);
      if (validateTemporary !== undefined) {
        await validateTemporary(temporary);
      }
      await link(temporary, destination);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  function ownsBody(body) {
    return typeof body === "string" && body.includes(ownershipMarker);
  }

  async function expectedAssetSizes(workDir, staged) {
    const paths = staged.map((asset) => asset.path);
    paths.push(join(workDir, "manifest.json"), join(workDir, "SHA256SUMS"));
    const expected = new Map();
    for (const path of paths) {
      const name = basename(path);
      assertExactAssetName(name);
      if (expected.has(name)) throw new Error("duplicate expected asset name");
      expected.set(name, (await stat(path)).size);
    }
    return expected;
  }

  function assertExactRemoteAssets(assets, expected) {
    if (!Array.isArray(assets)) {
      throw new Error("release assets are missing");
    }
    const actual = new Map();
    for (const asset of assets) {
      if (
        typeof asset?.name !== "string" ||
        !Number.isSafeInteger(asset?.size) ||
        asset.size < 0 ||
        actual.has(asset.name)
      ) {
        throw new Error("release has invalid or duplicate asset metadata");
      }
      actual.set(asset.name, asset.size);
    }
    if (
      actual.size !== expected.size ||
      [...actual].some(
        ([name, size]) => !expected.has(name) || expected.get(name) !== size,
      )
    ) {
      throw new Error("release asset names or sizes do not match exactly");
    }
  }

  function unknownPublishError(error) {
    error.publishStateUnknown = true;
    return error;
  }

  async function reconcilePublishedLatest(
    tag,
    operationError,
    { allowPromotion = true, knownPublished = false } = {},
  ) {
    let state;
    try {
      state = await viewTag(tag);
    } catch {
      throw unknownPublishError(
        operationError ?? new Error("published release state is unknown"),
      );
    }
    if (state.isDraft) {
      const error = operationError ?? new Error("release remained a draft");
      if (knownPublished) error.releasePublished = true;
      throw error;
    }

    let latestTag;
    try {
      latestTag = await viewLatestTag();
    } catch {
      throw unknownPublishError(
        operationError ?? new Error("latest release state is unknown"),
      );
    }
    if (latestTag === tag) return;

    if (!allowPromotion) {
      const error = operationError ?? new Error("release is not marked latest");
      error.releasePublished = true;
      throw error;
    }

    let promotionError;
    try {
      await run(["release", "edit", tag, "--repo", repo, "--latest"]);
    } catch (error) {
      promotionError = error;
    }
    return await reconcilePublishedLatest(tag, promotionError, {
      allowPromotion: false,
      knownPublished: true,
    });
  }

  async function publish(tag) {
    let editError;
    try {
      await run([
        "release",
        "edit",
        tag,
        "--repo",
        repo,
        "--draft=false",
        "--latest",
      ]);
    } catch (error) {
      editError = error;
    }
    return await reconcilePublishedLatest(tag, editError);
  }

  async function verifyExistingPublished(
    tag,
    manifest,
    workDir,
    staged,
    state,
  ) {
    if (manifest?.releaseTag !== tag) {
      throw new Error("local manifest releaseTag does not match target tag");
    }
    const expected = await expectedAssetSizes(workDir, staged);
    assertExactRemoteAssets(state.assets, expected);
    const directory = await mkdtemp(join(tmpdir(), "desktop-existing-release-"));
    const manifestPath = join(directory, "manifest.json");
    try {
      await downloadExact(tag, "manifest.json", manifestPath);
      const remoteManifest = parseJson(
        await readFile(manifestPath, "utf8"),
        "existing release manifest",
      );
      assertPublishedManifestEnvelope(remoteManifest, {
        expectedIds: staged.map((asset) => asset.id),
        product: manifest.product,
        tag,
      });
      if (
        remoteManifest.manifestDigest !== manifest.manifestDigest
      ) {
        throw new Error("existing published snapshot does not match manifest");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
    await publish(tag);
  }

  return {
    async readLatestManifest(expectedIds) {
      let tag;
      try {
        tag = await viewLatestTag();
      } catch (error) {
        if (error.noReleases || error.releaseNotFound) return null;
        throw error;
      }

      const directory = await mkdtemp(join(tmpdir(), "desktop-latest-manifest-"));
      const path = join(directory, "manifest.json");
      try {
        await downloadExact(tag, "manifest.json", path);
        const info = await stat(path);
        if (info.size <= 0 || info.size > 1024 ** 2) {
          throw new Error("latest manifest size is invalid");
        }
        const manifest = parseJson(
          await readFile(path, "utf8"),
          "latest manifest",
        );
        assertPreviousManifest(manifest, expectedIds);
        return { tag, manifest };
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },

    async stagePrevious(tag, previousAsset, destination) {
      if (
        !previousAsset ||
        !Number.isSafeInteger(previousAsset.size) ||
        previousAsset.size <= 0 ||
        !SHA256_PATTERN.test(previousAsset.sha256)
      ) {
        throw new Error("previous release asset metadata is invalid");
      }
      let actual;
      await downloadExact(
        tag,
        previousAsset.filename,
        destination,
        async (temporary) => {
          actual = await hashFile(temporary);
          if (
            actual.size !== previousAsset.size ||
            actual.sha256 !== previousAsset.sha256
          ) {
            throw new Error("previous release asset integrity mismatch");
          }
        },
      );
      return actual;
    },

    async writeMetadata(workDir, manifest, staged) {
      const installerAssets = [...staged].sort((left, right) =>
        codeUnitCompare(left.filename, right.filename),
      );
      const checksums = installerAssets
        .map((asset) => {
          assertExactAssetName(asset.filename);
          if (!SHA256_PATTERN.test(asset.sha256)) {
            throw new Error("staged release asset SHA256 is invalid");
          }
          return `${asset.sha256}  ${asset.filename}\n`;
        })
        .join("");
      await writeFile(
        join(workDir, "manifest.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
        { flag: "wx" },
      );
      await writeFile(join(workDir, "SHA256SUMS"), checksums, {
        flag: "wx",
      });
    },

    async createDraft(tag, manifest, workDir, staged) {
      assertTag(tag);
      try {
        await run([
          "release",
          "create",
          tag,
          "--repo",
          repo,
          "--draft",
          "--latest=false",
          "--title",
          tag,
          "--notes",
          releaseNotes,
        ]);
        return { alreadyPublished: false };
      } catch (error) {
        let state;
        try {
          state = await viewTag(tag, true);
        } catch {
          throw error;
        }
        if (state.isDraft) {
          if (ownsBody(state.body)) {
            error.draftCreated = true;
            throw error;
          }
          const conflict = new Error(
            "release draft is owned by a different synchronization run",
          );
          conflict.ownershipConflict = true;
          throw conflict;
        }
        try {
          await verifyExistingPublished(
            tag,
            manifest,
            workDir,
            staged,
            state,
          );
        } catch (recoveryError) {
          recoveryError.releasePublished = true;
          throw recoveryError;
        }
        return { alreadyPublished: true };
      }
    },

    async uploadAll(tag, workDir, staged) {
      assertTag(tag);
      const files = staged.map((asset) => asset.path);
      files.push(join(workDir, "manifest.json"), join(workDir, "SHA256SUMS"));
      await run(["release", "upload", tag, ...files, "--repo", repo]);
    },

    async verifyDraft(tag, _manifest, staged) {
      assertTag(tag);
      const { stdout } = await run([
        "release",
        "view",
        tag,
        "--repo",
        repo,
        "--json",
        "tagName,isDraft,assets",
      ]);
      const release = parseJson(stdout, "draft verification");
      if (release?.tagName !== tag || release?.isDraft !== true) {
        throw new Error("release is not the expected draft");
      }
      if (!Array.isArray(release.assets)) {
        throw new Error("draft assets are missing");
      }

      const workDir = staged.length > 0 ? dirname(staged[0].path) : null;
      if (workDir === null) throw new Error("staged assets must not be empty");
      const expected = await expectedAssetSizes(workDir, staged);
      assertExactRemoteAssets(release.assets, expected);
    },

    async publishDraft(tag) {
      assertTag(tag);
      return await publish(tag);
    },

    async deleteDraft(tag) {
      assertTag(tag);
      let state;
      try {
        state = await viewTag(tag);
      } catch (error) {
        if (error.releaseNotFound) return;
        throw error;
      }
      if (!state.isDraft) {
        throw new Error("refusing to delete a non-draft release");
      }
      if (!ownsBody(state.body)) {
        throw new Error("refusing to delete a draft without this run's ownership marker");
      }
      await run([
        "release",
        "delete",
        tag,
        "--repo",
        repo,
        "--cleanup-tag",
        "--yes",
      ]);
    },
  };
}
