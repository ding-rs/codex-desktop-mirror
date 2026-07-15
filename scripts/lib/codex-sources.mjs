import { rm } from "node:fs/promises";

import {
  downloadAndHash,
  fetchJsonWithRetry,
  fetchWithRetry,
} from "./http.mjs";
import { MAX_ASSET_SIZE } from "./snapshot.mjs";

const STORE_PRODUCT_ID = "9PLM9XGG6VKS";
const STORE_ENDPOINT =
  "https://msft-store.tplant.com.au/api/Packages?inputform=productid&Id=9PLM9XGG6VKS&environment=Production";
const MONIKER_PREFIX = "OpenAI.Codex_";
const MICROSOFT_DELIVERY_SUFFIX = "delivery.mp.microsoft.com";
const DEFAULT_PROBE_TIMEOUT_MS = 15_000;
const DEFAULT_METADATA_MAX_BYTES = 1024 ** 2;
const PROBE_REDIRECT_PROTOCOLS = ["https:"];

const ASSETS = [
  {
    id: "darwin-arm64-dmg",
    filename: "Codex-macOS-arm64.dmg",
    sourceEndpoint:
      "https://persistent.oaistatic.com/codex-app-prod/Codex.dmg",
    kind: "direct",
  },
  {
    id: "darwin-x64-dmg",
    filename: "Codex-macOS-x64.dmg",
    sourceEndpoint:
      "https://persistent.oaistatic.com/codex-app-prod/Codex-latest-x64.dmg",
    kind: "direct",
  },
  {
    id: "win32-x64-msix",
    filename: "Codex-Windows-x64.msix",
    sourceEndpoint: STORE_ENDPOINT,
    kind: "store",
  },
  {
    id: "win32-x64-installer",
    filename: "Codex-Windows-Installer.exe",
    sourceEndpoint:
      "https://get.microsoft.com/installer/download/9PLM9XGG6VKS?cid=website_cta_psi",
    kind: "store-wrapper",
  },
];

const STRONG_ETAG_PATTERN = /^"[\u0021\u0023-\u007e\u0080-\u00ff]+"$/;
const AZURE_HEXADECIMAL_ETAG_PATTERN = /^0x[0-9a-f]+$/i;
const HTTP_DATE_PATTERN =
  /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

function positiveSafeInteger(value, field) {
  let normalized = value;
  if (typeof normalized === "string" && /^\d+$/.test(normalized)) {
    normalized = Number(normalized);
  }
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  if (normalized >= MAX_ASSET_SIZE) {
    throw new Error(`${field} must be less than 2 GiB`);
  }
  return normalized;
}

function stableIdentityError(detail) {
  return new Error(`stable source identity unavailable: ${detail}`);
}

export function stableDirectFingerprint({
  etag,
  lastModified,
  contentLength,
}) {
  let size;
  try {
    size = positiveSafeInteger(contentLength, "content-length");
  } catch (error) {
    throw stableIdentityError(error.message);
  }

  const hasStableEtag =
    typeof etag === "string" &&
    (STRONG_ETAG_PATTERN.test(etag) ||
      AZURE_HEXADECIMAL_ETAG_PATTERN.test(etag));
  if (hasStableEtag) {
    return `etag:${etag}|size:${size}`;
  }

  const parsedLastModified =
    typeof lastModified === "string" ? Date.parse(lastModified) : Number.NaN;
  if (
    typeof lastModified !== "string" ||
    !HTTP_DATE_PATTERN.test(lastModified) ||
    !Number.isFinite(parsedLastModified) ||
    new Date(parsedLastModified).toUTCString() !== lastModified
  ) {
    throw stableIdentityError(
      "neither ETag nor Last-Modified is accepted stable metadata",
    );
  }
  return `last-modified:${lastModified}|size:${size}`;
}

function assertSafeFingerprintPart(value, field) {
  if (value.includes("|") || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`Store package ${field} contains unsafe characters`);
  }
}

function normalizeMicrosoftDeliveryUrl(value, field) {
  let parsedUrl;
  try {
    parsedUrl = new URL(value);
  } catch {
    throw new Error(`${field} is invalid`);
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error(`${field} must not contain credentials`);
  }
  if (parsedUrl.hash) {
    throw new Error(`${field} must not contain a fragment`);
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(`${field} must use HTTP or HTTPS`);
  }
  if (parsedUrl.port) {
    throw new Error(`${field} must not use a non-default port`);
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  if (
    hostname !== MICROSOFT_DELIVERY_SUFFIX &&
    !hostname.endsWith(`.${MICROSOFT_DELIVERY_SUFFIX}`)
  ) {
    throw new Error(`${field} must use a reviewed Microsoft delivery host`);
  }
  return parsedUrl;
}

export function assertMicrosoftDeliveryUrl(value) {
  return normalizeMicrosoftDeliveryUrl(value, "Microsoft delivery URL");
}

function normalizeStorePackage(candidate) {
  const { packagemoniker: moniker, packagefilename: filename } = candidate;
  const resolvedUrl = candidate.packagedownloadurl;

  assertSafeFingerprintPart(moniker, "moniker");
  assertSafeFingerprintPart(filename, "filename");

  if (typeof resolvedUrl !== "string" || resolvedUrl.length === 0) {
    throw new Error("Store package download URL is missing");
  }
  if (resolvedUrl.includes("#")) {
    throw new Error("Store package download URL must not contain a fragment");
  }
  const normalizedUrl = normalizeMicrosoftDeliveryUrl(
    resolvedUrl,
    "Store package download URL",
  );

  const size = positiveSafeInteger(
    candidate.packagefilesize,
    "Store package size",
  );
  return { moniker, filename, resolvedUrl: normalizedUrl.href, size };
}

function selectStorePackage(packages) {
  if (!Array.isArray(packages)) {
    throw new Error("Store metadata must be an array");
  }

  const candidates = packages.filter(
    (candidate) =>
      candidate &&
      typeof candidate.packagemoniker === "string" &&
      candidate.packagemoniker.startsWith(MONIKER_PREFIX) &&
      /_x64__/i.test(candidate.packagemoniker) &&
      typeof candidate.packagefilename === "string" &&
      /_x64(?:_|\.Msix$)/i.test(candidate.packagefilename) &&
      /\.Msix$/i.test(candidate.packagefilename),
  );
  if (candidates.length === 0) {
    throw new Error(
      `Store metadata has no matching x64 Codex MSIX for ${STORE_PRODUCT_ID}`,
    );
  }
  if (candidates.length > 1) {
    throw new Error(
      `ambiguous Codex MSIX candidates for ${STORE_PRODUCT_ID}`,
    );
  }
  return normalizeStorePackage(candidates[0]);
}

function probeRequestOptions(options) {
  return {
    headerTimeoutMs: options.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS,
    backoffBaseMs: options.backoffBaseMs ?? 500,
    allowedRedirectProtocols: PROBE_REDIRECT_PROTOCOLS,
    maxRedirects: options.maxRedirects ?? 5,
  };
}

async function headSource(fetchImpl, url, options) {
  const response = await fetchWithRetry(
    fetchImpl,
    url,
    { method: "HEAD", signal: options.signal },
    options.attempts ?? 3,
    probeRequestOptions(options),
  );
  return {
    response,
    resolvedUrl: response.url || url,
  };
}

function contentLengthFromHeaders(headers) {
  const value = headers.get("content-length");
  return positiveSafeInteger(value, "content-length");
}

async function probeDirectAsset(fetchImpl, asset, options) {
  const { response, resolvedUrl } = await headSource(
    fetchImpl,
    asset.sourceEndpoint,
    options,
  );
  const expectedSize = contentLengthFromHeaders(response.headers);
  return {
    id: asset.id,
    filename: asset.filename,
    sourceEndpoint: asset.sourceEndpoint,
    sourceFingerprint: stableDirectFingerprint({
      etag: response.headers.get("etag"),
      lastModified: response.headers.get("last-modified"),
      contentLength: expectedSize,
    }),
    resolvedUrl,
    expectedSize,
  };
}

function probeStoreAsset(asset, storePackage) {
  return {
    id: asset.id,
    filename: asset.filename,
    sourceEndpoint: asset.sourceEndpoint,
    sourceFingerprint:
      `moniker:${storePackage.moniker}|file:${storePackage.filename}` +
      `|size:${storePackage.size}`,
    resolvedUrl: storePackage.resolvedUrl,
    // Download staging must recheck the final response host, require the
    // downloaded size to exactly equal expectedSize, and verify both MSIX and
    // EXE Authenticode signatures with signtool before publishing.
    expectedSize: storePackage.size,
  };
}

async function probeStoreWrapper(fetchImpl, asset, storePackage, options) {
  const { response, resolvedUrl } = await headSource(
    fetchImpl,
    asset.sourceEndpoint,
    options,
  );
  const wrapperSize = contentLengthFromHeaders(response.headers);

  return {
    id: asset.id,
    filename: asset.filename,
    sourceEndpoint: asset.sourceEndpoint,
    sourceFingerprint:
      `store-moniker:${storePackage.moniker}|` +
      `store-file:${storePackage.filename}|` +
      `store-size:${storePackage.size}|wrapper-size:${wrapperSize}`,
    resolvedUrl,
    expectedSize: wrapperSize,
  };
}

export async function probeCodexAssets(fetchImpl, options = {}) {
  const packages = await fetchJsonWithRetry(
    fetchImpl,
    STORE_ENDPOINT,
    { method: "GET", signal: options.signal },
    options.attempts ?? 3,
    {
      ...probeRequestOptions(options),
      bodyTimeoutMs:
        options.metadataBodyTimeoutMs ??
        options.probeTimeoutMs ??
        DEFAULT_PROBE_TIMEOUT_MS,
      maxBytes: options.metadataMaxBytes ?? DEFAULT_METADATA_MAX_BYTES,
    },
  );
  const storePackage = selectStorePackage(packages);

  const probes = [];
  for (const asset of ASSETS) {
    if (asset.kind === "store") {
      probes.push(probeStoreAsset(asset, storePackage));
    } else if (asset.kind === "store-wrapper") {
      probes.push(
        await probeStoreWrapper(fetchImpl, asset, storePackage, options),
      );
    } else {
      probes.push(await probeDirectAsset(fetchImpl, asset, options));
    }
  }
  return probes;
}

function definitionForProbe(probe) {
  const definition = ASSETS.find((asset) => asset.id === probe?.id);
  if (!definition || probe.filename !== definition.filename) {
    throw new Error("changed asset must use a fixed Codex id and filename");
  }
  if (
    typeof probe.resolvedUrl !== "string" ||
    probe.resolvedUrl.length === 0
  ) {
    throw new Error(`${definition.id} resolved download URL is missing`);
  }
  return definition;
}

function stagingDownloadOptions(options, validateResponse, expectedSize) {
  return {
    attempts: options.downloadAttempts ?? options.attempts ?? 3,
    backoffBaseMs: options.backoffBaseMs,
    headerTimeoutMs: options.downloadHeaderTimeoutMs,
    inactivityTimeoutMs: options.downloadInactivityTimeoutMs,
    signal: options.signal,
    maxBytes: expectedSize + 1,
    ...(validateResponse ? { validateResponse } : {}),
  };
}

function assertOfficialHttpsUrl(value, hostname, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} final URL is invalid`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.toLowerCase() !== hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    parsed.port
  ) {
    throw new Error(`${label} final URL must use the expected HTTPS host`);
  }
}

function responseContentLength(response, field) {
  return positiveSafeInteger(response?.headers?.get?.("content-length"), field);
}

export function createCodexSource({
  fetchImpl,
  verifyWindowsSignature,
  probeOptions = {},
}) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetchImpl must be a function");
  }
  if (typeof verifyWindowsSignature !== "function") {
    throw new TypeError("verifyWindowsSignature must be a function");
  }

  return {
    probe() {
      return probeCodexAssets(fetchImpl, probeOptions);
    },

    async stageChanged(probe, destination) {
      const definition = definitionForProbe(probe);
      const expectedSize = positiveSafeInteger(
        probe.expectedSize,
        `${definition.id} expectedSize`,
      );
      let validateResponse;
      if (definition.id === "win32-x64-msix") {
        validateResponse = (response) => {
          if (typeof response?.url !== "string" || response.url.length === 0) {
            throw new Error("Microsoft delivery final response URL is missing");
          }
          assertMicrosoftDeliveryUrl(response.url);
          const advertised = response?.headers?.get?.("content-length");
          if (
            advertised !== null &&
            advertised !== undefined &&
            positiveSafeInteger(advertised, "MSIX content-length") !==
              expectedSize
          ) {
            throw new Error("MSIX content-length does not match expectedSize");
          }
        };
      } else if (definition.kind === "direct") {
        validateResponse = (response) => {
          assertOfficialHttpsUrl(
            response?.url,
            "persistent.oaistatic.com",
            "Codex DMG",
          );
          const fingerprint = stableDirectFingerprint({
            etag: response.headers.get("etag"),
            lastModified: response.headers.get("last-modified"),
            contentLength: responseContentLength(
              response,
              "DMG content-length",
            ),
          });
          if (fingerprint !== probe.sourceFingerprint) {
            throw new Error("DMG GET fingerprint does not match probe");
          }
        };
      } else if (definition.id === "win32-x64-installer") {
        validateResponse = (response) => {
          assertOfficialHttpsUrl(
            response?.url,
            "get.microsoft.com",
            "Codex installer",
          );
          if (
            responseContentLength(response, "installer content-length") !==
            expectedSize
          ) {
            throw new Error(
              "installer content-length does not match expectedSize",
            );
          }
        };
      }

      const file = await downloadAndHash(
        fetchImpl,
        probe.resolvedUrl,
        destination,
        stagingDownloadOptions(probeOptions, validateResponse, expectedSize),
      );

      if (file.size !== expectedSize) {
        await rm(destination, { force: true });
        throw new Error(`${definition.id} downloaded size does not match metadata`);
      }

      if (
        definition.id === "win32-x64-msix" ||
        definition.id === "win32-x64-installer"
      ) {
        try {
          await verifyWindowsSignature(destination);
        } catch {
          await rm(destination, { force: true });
          throw new Error(
            `${definition.id} Windows signature verification failed`,
          );
        }
      }

      return file;
    },
  };
}
