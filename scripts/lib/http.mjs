import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { rm, stat } from "node:fs/promises";
import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { MAX_ASSET_SIZE } from "./snapshot.mjs";

const DEFAULT_USER_AGENT = "ding-rs-desktop-mirror/1.0";
const DEFAULT_HEADER_TIMEOUT_MS = 30_000;
const DEFAULT_INACTIVITY_TIMEOUT_MS = 120_000;
const DEFAULT_BACKOFF_BASE_MS = 500;
const DEFAULT_JSON_BODY_TIMEOUT_MS = 15_000;
const DEFAULT_JSON_MAX_BYTES = 1024 ** 2;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_CANCEL_TIMEOUT_MS = 50;
const MAX_ATTEMPTS = 10;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const NON_RETRYABLE_FS_CODES = new Set([
  "EACCES",
  "EEXIST",
  "EISDIR",
  "ENOENT",
  "ENOSPC",
  "ENOTDIR",
  "EPERM",
  "EROFS",
]);

class SanitizedOperationError extends Error {
  constructor(message, { code, retryable = false } = {}) {
    super(message);
    this.name = "Error";
    if (code) this.code = code;
    Object.defineProperty(this, "retryable", { value: retryable });
  }
}

function safeUrlForError(url) {
  try {
    const parsed = new URL(String(url));
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "requested URL";
  }
}

function assertAttempts(attempts) {
  if (
    !Number.isSafeInteger(attempts) ||
    attempts <= 0 ||
    attempts > MAX_ATTEMPTS
  ) {
    throw new RangeError(
      `attempts must be a positive integer no greater than ${MAX_ATTEMPTS}`,
    );
  }
}

function assertPositiveTimeout(value, field) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${field} must be a positive finite number`);
  }
}

function assertBackoff(value) {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError("backoffBaseMs must be a non-negative finite number");
  }
}

function assertMaxBytes(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError("maxBytes must be a positive safe integer");
  }
  if (value > MAX_ASSET_SIZE) {
    throw new RangeError(
      `maxBytes must be no greater than the shared limit ${MAX_ASSET_SIZE}`,
    );
  }
}

function abortError(operation, url) {
  return new SanitizedOperationError(
    `${operation} aborted for ${safeUrlForError(url)}`,
    { code: "ABORT_ERR" },
  );
}

function timeoutError(operation, url) {
  return new SanitizedOperationError(
    `${operation} timed out for ${safeUrlForError(url)}`,
    { code: "ETIMEDOUT", retryable: true },
  );
}

function isRetryableStatus(status) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

async function cancelBody(
  response,
  { signal, timeoutMs = DEFAULT_CANCEL_TIMEOUT_MS } = {},
) {
  const body = response?.body;
  if (typeof body?.cancel !== "function") return;

  let timer;
  let onAbort;
  const boundedWait = new Promise((resolve) => {
    const finish = () => resolve();
    timer = setTimeout(finish, timeoutMs);
    onAbort = finish;
    if (signal?.aborted) finish();
    else signal?.addEventListener("abort", onAbort, { once: true });
  });
  try {
    await Promise.race([
      Promise.resolve()
        .then(() => body.cancel())
        .catch(() => {}),
      boundedWait,
    ]);
  } catch {
    // Cancellation is best-effort; never expose a body error or its URL.
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function normalizeRedirectPolicy(options) {
  if (options.allowedRedirectProtocols === undefined) return null;
  if (
    !Array.isArray(options.allowedRedirectProtocols) ||
    options.allowedRedirectProtocols.length === 0
  ) {
    throw new RangeError(
      "allowedRedirectProtocols must be a non-empty array",
    );
  }

  const allowedProtocols = new Set();
  for (const protocol of options.allowedRedirectProtocols) {
    if (
      typeof protocol !== "string" ||
      !/^[a-z][a-z0-9+.-]*:$/.test(protocol)
    ) {
      throw new RangeError(
        "allowedRedirectProtocols contains an invalid protocol",
      );
    }
    allowedProtocols.add(protocol);
  }

  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0) {
    throw new RangeError("maxRedirects must be a non-negative safe integer");
  }
  return { allowedProtocols, maxRedirects };
}

function secureRedirectError(message, contextUrl, code) {
  return new SanitizedOperationError(
    `${message} for ${safeUrlForError(contextUrl)}`,
    { code },
  );
}

function validateRedirectUrl(value, baseUrl, policy, label, contextUrl) {
  let parsed;
  try {
    parsed = baseUrl === undefined ? new URL(value) : new URL(value, baseUrl);
  } catch {
    throw secureRedirectError(
      `${label} is invalid`,
      contextUrl,
      "INVALID_REDIRECT_URL",
    );
  }
  if (parsed.username || parsed.password) {
    throw secureRedirectError(
      `${label} must not contain credentials`,
      contextUrl,
      "REDIRECT_CREDENTIALS",
    );
  }
  if (!policy.allowedProtocols.has(parsed.protocol)) {
    throw secureRedirectError(
      `${label} protocol is not allowed`,
      contextUrl,
      "REDIRECT_PROTOCOL",
    );
  }
  return parsed;
}

function createHeaderDeadline(externalSignal, timeoutMs) {
  const controller = new AbortController();
  const requestSignal = externalSignal
    ? AbortSignal.any([controller.signal, externalSignal])
    : controller.signal;
  let timedOut = false;
  let externallyAborted = false;
  let rejectDeadline;

  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
    rejectDeadline(new Error("header deadline"));
  }, timeoutMs);

  const onExternalAbort = () => {
    externallyAborted = true;
    controller.abort();
    rejectDeadline(new Error("external abort"));
  };
  if (externalSignal) {
    if (externalSignal.aborted) onExternalAbort();
    else externalSignal.addEventListener("abort", onExternalAbort, {
      once: true,
    });
  }

  return {
    deadline,
    signal: requestSignal,
    get externallyAborted() {
      return externallyAborted;
    },
    get timedOut() {
      return timedOut;
    },
    cleanup() {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
    },
  };
}

async function waitForBackoff(milliseconds, signal) {
  if (signal?.aborted) return false;
  if (milliseconds === 0) return true;

  return await new Promise((resolve) => {
    let settled = false;
    const finish = (completed) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(completed);
    };
    const onAbort = () => finish(false);
    const timer = setTimeout(() => finish(true), milliseconds);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function normalizeFetchError(error, deadline, url) {
  if (deadline.externallyAborted) return abortError("request", url);
  if (deadline.timedOut) return timeoutError("request headers", url);
  if (error instanceof SanitizedOperationError) return error;
  return new SanitizedOperationError(
    `request failed for ${safeUrlForError(url)}`,
    { code: "NETWORK_ERROR", retryable: true },
  );
}

async function fetchBeforeDeadline(
  fetchImpl,
  url,
  init,
  deadline,
  redirect,
) {
  let acceptResponse = true;
  const request = Promise.resolve().then(() =>
    fetchImpl(url, {
      ...init,
      redirect,
      signal: deadline.signal,
    }),
  );
  void request.then(
    (response) => {
      if (!acceptResponse) void cancelBody(response);
    },
    () => {},
  );
  try {
    return await Promise.race([request, deadline.deadline]);
  } finally {
    acceptResponse = false;
  }
}

async function fetchWithSecureRedirects(
  fetchImpl,
  url,
  init,
  deadline,
  policy,
) {
  let currentUrl = validateRedirectUrl(
    url,
    undefined,
    policy,
    "request URL",
    url,
  ).href;
  let redirectCount = 0;

  while (true) {
    const response = await fetchBeforeDeadline(
      fetchImpl,
      currentUrl,
      init,
      deadline,
      "manual",
    );
    let responseUrl;
    try {
      responseUrl = validateRedirectUrl(
        response.url || currentUrl,
        undefined,
        policy,
        "response URL",
        currentUrl,
      ).href;
    } catch (error) {
      await cancelBody(response, { signal: deadline.signal });
      throw error;
    }

    if (!REDIRECT_STATUSES.has(Number(response.status))) return response;

    let nextUrl;
    try {
      if (redirectCount >= policy.maxRedirects) {
        throw secureRedirectError(
          `too many redirects (limit ${policy.maxRedirects})`,
          currentUrl,
          "TOO_MANY_REDIRECTS",
        );
      }
      const location = response.headers?.get?.("location");
      if (typeof location !== "string" || location.length === 0) {
        throw secureRedirectError(
          "redirect Location is missing",
          currentUrl,
          "MISSING_REDIRECT_LOCATION",
        );
      }
      nextUrl = validateRedirectUrl(
        location,
        responseUrl,
        policy,
        "redirect Location",
        currentUrl,
      ).href;
    } finally {
      await cancelBody(response, { signal: deadline.signal });
    }

    currentUrl = nextUrl;
    redirectCount += 1;
  }
}

export async function fetchWithRetry(
  fetchImpl,
  url,
  init = {},
  attempts = 3,
  options = {},
) {
  assertAttempts(attempts);
  const headerTimeoutMs =
    options.headerTimeoutMs ?? DEFAULT_HEADER_TIMEOUT_MS;
  const backoffBaseMs = options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
  const redirectPolicy = normalizeRedirectPolicy(options);
  assertPositiveTimeout(headerTimeoutMs, "headerTimeoutMs");
  assertBackoff(backoffBaseMs);

  const externalSignal = init.signal;
  if (externalSignal?.aborted) throw abortError("request", url);

  const baseHeaders = new Headers({ "user-agent": DEFAULT_USER_AGENT });
  for (const [name, value] of new Headers(init.headers)) {
    baseHeaders.set(name, value);
  }

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const deadline = createHeaderDeadline(externalSignal, headerTimeoutMs);
    try {
      const requestInit = { ...init, headers: new Headers(baseHeaders) };
      const response = redirectPolicy
        ? await fetchWithSecureRedirects(
            fetchImpl,
            url,
            requestInit,
            deadline,
            redirectPolicy,
          )
        : await fetchBeforeDeadline(
            fetchImpl,
            url,
            requestInit,
            deadline,
            "follow",
          );
      deadline.cleanup();

      if (!response.ok) {
        await cancelBody(response);
        const status = Number(response.status);
        throw new SanitizedOperationError(
          `HTTP ${String(response.status)} for ${safeUrlForError(url)}`,
          {
            code: Number.isFinite(status) ? `HTTP_${status}` : "HTTP_ERROR",
            retryable: Number.isFinite(status) && isRetryableStatus(status),
          },
        );
      }
      return response;
    } catch (error) {
      lastError = normalizeFetchError(error, deadline, url);
    } finally {
      deadline.cleanup();
    }

    if (!lastError.retryable || attempt === attempts) break;
    if (externalSignal?.aborted) throw abortError("request", url);
    const continued = await waitForBackoff(
      backoffBaseMs * 2 ** (attempt - 1),
      externalSignal,
    );
    if (!continued) throw abortError("request", url);
  }

  throw lastError;
}

function createAbsoluteBodyGuard(externalSignal, timeoutMs) {
  const controller = new AbortController();
  const signal = externalSignal
    ? AbortSignal.any([controller.signal, externalSignal])
    : controller.signal;
  let timedOut = false;
  let externallyAborted = externalSignal?.aborted ?? false;

  const onExternalAbort = () => {
    externallyAborted = true;
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  return {
    signal,
    get externallyAborted() {
      return externallyAborted;
    },
    get timedOut() {
      return timedOut;
    },
    cleanup() {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
    },
  };
}

function normalizeJsonBodyError(error, guard, url) {
  if (guard?.externallyAborted) return abortError("metadata request", url);
  if (guard?.timedOut) return timeoutError("metadata body", url);
  if (error instanceof SanitizedOperationError) return error;
  return new SanitizedOperationError(
    `metadata body failed for ${safeUrlForError(url)}`,
    { code: "METADATA_BODY_ERROR", retryable: true },
  );
}

async function readBoundedJsonBody(
  response,
  url,
  { bodyTimeoutMs, maxBytes, signal },
) {
  if (!response.body) {
    throw new SanitizedOperationError(
      `metadata body is empty for ${safeUrlForError(url)}`,
      { code: "EMPTY_METADATA_BODY", retryable: true },
    );
  }

  const advertised = response.headers?.get?.("content-length");
  if (advertised !== null && advertised !== undefined) {
    const advertisedSize = /^\d+$/.test(advertised)
      ? Number(advertised)
      : Number.NaN;
    if (!Number.isSafeInteger(advertisedSize) || advertisedSize < 0) {
      await cancelBody(response);
      throw new SanitizedOperationError(
        `metadata has invalid content-length for ${safeUrlForError(url)}`,
        { code: "INVALID_CONTENT_LENGTH", retryable: true },
      );
    }
    if (advertisedSize > maxBytes) {
      await cancelBody(response);
      throw new SanitizedOperationError(
        `metadata exceeds ${maxBytes} bytes for ${safeUrlForError(url)}`,
        { code: "METADATA_TOO_LARGE", retryable: true },
      );
    }
  }

  const guard = createAbsoluteBodyGuard(signal, bodyTimeoutMs);
  const chunks = [];
  let size = 0;
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      const nextSize = size + chunk.length;
      if (nextSize > maxBytes) {
        callback(
          new SanitizedOperationError(
            `metadata exceeds ${maxBytes} bytes for ${safeUrlForError(url)}`,
            { code: "METADATA_TOO_LARGE", retryable: true },
          ),
        );
        return;
      }
      size = nextSize;
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });

  try {
    await pipeline(Readable.fromWeb(response.body), sink, {
      signal: guard.signal,
    });
  } catch (error) {
    await cancelBody(response);
    throw normalizeJsonBodyError(error, guard, url);
  } finally {
    guard.cleanup();
  }

  try {
    return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
  } catch {
    throw new SanitizedOperationError(
      `metadata JSON is invalid for ${safeUrlForError(url)}`,
      { code: "INVALID_JSON", retryable: true },
    );
  }
}

export async function fetchJsonWithRetry(
  fetchImpl,
  url,
  init = {},
  attempts = 3,
  options = {},
) {
  assertAttempts(attempts);
  const headerTimeoutMs =
    options.headerTimeoutMs ?? DEFAULT_HEADER_TIMEOUT_MS;
  const bodyTimeoutMs =
    options.bodyTimeoutMs ?? DEFAULT_JSON_BODY_TIMEOUT_MS;
  const backoffBaseMs = options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_JSON_MAX_BYTES;
  assertPositiveTimeout(headerTimeoutMs, "headerTimeoutMs");
  assertPositiveTimeout(bodyTimeoutMs, "bodyTimeoutMs");
  assertBackoff(backoffBaseMs);
  assertMaxBytes(maxBytes);

  const signal = init.signal;
  if (signal?.aborted) throw abortError("metadata request", url);

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchWithRetry(fetchImpl, url, init, 1, {
        headerTimeoutMs,
        backoffBaseMs: 0,
        allowedRedirectProtocols: options.allowedRedirectProtocols,
        maxRedirects: options.maxRedirects,
      });
      return await readBoundedJsonBody(response, url, {
        bodyTimeoutMs,
        maxBytes,
        signal,
      });
    } catch (error) {
      lastError =
        error instanceof SanitizedOperationError
          ? error
          : normalizeJsonBodyError(error, null, url);
    }

    if (!lastError.retryable || attempt === attempts) break;
    if (signal?.aborted) throw abortError("metadata request", url);
    const continued = await waitForBackoff(
      backoffBaseMs * 2 ** (attempt - 1),
      signal,
    );
    if (!continued) throw abortError("metadata request", url);
  }

  throw lastError;
}

function parseAdvertisedLength(headers, maxBytes, url) {
  const raw = headers?.get?.("content-length");
  if (raw === null || raw === undefined) return null;
  if (!/^\d+$/.test(raw)) {
    throw new SanitizedOperationError(
      `download has invalid content-length for ${safeUrlForError(url)}`,
      { code: "INVALID_CONTENT_LENGTH" },
    );
  }
  const size = Number(raw);
  if (!Number.isSafeInteger(size) || size <= 0) {
    throw new SanitizedOperationError(
      `download has invalid content-length for ${safeUrlForError(url)}`,
      { code: "INVALID_CONTENT_LENGTH" },
    );
  }
  if (size >= maxBytes) {
    throw new SanitizedOperationError(
      `download size must be less than ${maxBytes} bytes for ${safeUrlForError(url)}`,
      { code: "ASSET_TOO_LARGE" },
    );
  }
  return size;
}

function createInactivityGuard(externalSignal, timeoutMs) {
  const controller = new AbortController();
  let timer;
  let timedOut = false;
  let externallyAborted = false;

  const onExternalAbort = () => {
    externallyAborted = true;
    controller.abort();
  };
  if (externalSignal) {
    if (externalSignal.aborted) onExternalAbort();
    else externalSignal.addEventListener("abort", onExternalAbort, {
      once: true,
    });
  }

  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
  };

  return {
    signal: controller.signal,
    reset,
    get externallyAborted() {
      return externallyAborted;
    },
    get timedOut() {
      return timedOut;
    },
    cleanup() {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
    },
  };
}

function safeErrorCode(error, fallback) {
  return typeof error?.code === "string" && /^[A-Z0-9_]+$/.test(error.code)
    ? error.code
    : fallback;
}

function normalizeDownloadError(error, guard, url) {
  if (guard?.externallyAborted) return abortError("download", url);
  if (guard?.timedOut) return timeoutError("download body inactivity", url);
  if (error instanceof SanitizedOperationError) return error;

  const code = safeErrorCode(error, "DOWNLOAD_FAILED");
  return new SanitizedOperationError(
    `download failed for ${safeUrlForError(url)}`,
    { code, retryable: !NON_RETRYABLE_FS_CODES.has(code) },
  );
}

async function runDownloadAttempt(
  fetchImpl,
  url,
  destination,
  {
    headerTimeoutMs,
    inactivityTimeoutMs,
    maxBytes,
    signal,
    validateResponse,
  },
) {
  const response = await fetchWithRetry(
    fetchImpl,
    url,
    { signal },
    1,
    { headerTimeoutMs, backoffBaseMs: 0 },
  );

  if (validateResponse !== undefined) {
    if (typeof validateResponse !== "function") {
      await cancelBody(response);
      throw new TypeError("validateResponse must be a function");
    }
    try {
      await validateResponse(response);
    } catch {
      await cancelBody(response);
      throw new SanitizedOperationError(
        `download response validation failed for ${safeUrlForError(url)}`,
        { code: "RESPONSE_REJECTED" },
      );
    }
  }

  try {
    parseAdvertisedLength(response.headers, maxBytes, url);
  } catch (error) {
    await cancelBody(response);
    throw error;
  }
  if (!response.body) {
    throw new SanitizedOperationError(
      `empty response body for ${safeUrlForError(url)}`,
      { code: "EMPTY_BODY", retryable: true },
    );
  }

  const guard = createInactivityGuard(signal, inactivityTimeoutMs);
  const hash = createHash("sha256");
  let size = 0;
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      guard.reset();
      const nextSize = size + chunk.length;
      if (nextSize >= maxBytes) {
        callback(
          new SanitizedOperationError(
            `download size must be less than ${maxBytes} bytes for ${safeUrlForError(url)}`,
            { code: "ASSET_TOO_LARGE" },
          ),
        );
        return;
      }
      size = nextSize;
      hash.update(chunk);
      callback(null, chunk);
    },
  });

  const source = Readable.fromWeb(response.body);
  const output = createWriteStream(destination, { flags: "wx" });
  let opened = false;
  output.once("open", () => {
    opened = true;
  });
  guard.reset();

  try {
    await pipeline(source, meter, output, { signal: guard.signal });
    const info = await stat(destination);
    if (size <= 0 || info.size <= 0) {
      throw new SanitizedOperationError(
        `empty downloaded file for ${safeUrlForError(url)}`,
        { code: "EMPTY_DOWNLOAD", retryable: true },
      );
    }
    if (info.size !== size) {
      throw new SanitizedOperationError(
        `download size verification failed for ${safeUrlForError(url)}`,
        { code: "SIZE_MISMATCH", retryable: true },
      );
    }
    return { size, sha256: hash.digest("hex") };
  } catch (error) {
    if (opened) await rm(destination, { force: true });
    throw normalizeDownloadError(error, guard, url);
  } finally {
    guard.cleanup();
  }
}

export async function downloadAndHash(
  fetchImpl,
  url,
  destination,
  options = {},
) {
  const attempts = options.attempts ?? 3;
  const backoffBaseMs = options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
  const headerTimeoutMs =
    options.headerTimeoutMs ?? DEFAULT_HEADER_TIMEOUT_MS;
  const inactivityTimeoutMs =
    options.inactivityTimeoutMs ?? DEFAULT_INACTIVITY_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? MAX_ASSET_SIZE;
  const signal = options.signal;
  const validateResponse = options.validateResponse;

  assertAttempts(attempts);
  assertBackoff(backoffBaseMs);
  assertPositiveTimeout(headerTimeoutMs, "headerTimeoutMs");
  assertPositiveTimeout(inactivityTimeoutMs, "inactivityTimeoutMs");
  assertMaxBytes(maxBytes);
  if (signal?.aborted) throw abortError("download", url);

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await runDownloadAttempt(fetchImpl, url, destination, {
        headerTimeoutMs,
        inactivityTimeoutMs,
        maxBytes,
        signal,
        validateResponse,
      });
    } catch (error) {
      lastError =
        error instanceof SanitizedOperationError
          ? error
          : normalizeDownloadError(error, null, url);
    }

    if (!lastError.retryable || attempt === attempts) break;
    if (signal?.aborted) throw abortError("download", url);
    const continued = await waitForBackoff(
      backoffBaseMs * 2 ** (attempt - 1),
      signal,
    );
    if (!continued) throw abortError("download", url);
  }

  throw lastError;
}
