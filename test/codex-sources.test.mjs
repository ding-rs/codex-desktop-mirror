import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { inspect } from "node:util";

import {
  downloadAndHash,
  fetchJsonWithRetry,
  fetchWithRetry,
} from "../scripts/lib/http.mjs";
import {
  assertMicrosoftDeliveryUrl,
  createCodexSource,
  probeCodexAssets,
  stableDirectFingerprint,
} from "../scripts/lib/codex-sources.mjs";
import { MAX_ASSET_SIZE } from "../scripts/lib/snapshot.mjs";

const ARM64_ENDPOINT =
  "https://persistent.oaistatic.com/codex-app-prod/Codex.dmg";
const X64_ENDPOINT =
  "https://persistent.oaistatic.com/codex-app-prod/Codex-latest-x64.dmg";
const STORE_ENDPOINT =
  "https://msft-store.tplant.com.au/api/Packages?inputform=productid&Id=9PLM9XGG6VKS&environment=Production";
const WRAPPER_ENDPOINT =
  "https://get.microsoft.com/installer/download/9PLM9XGG6VKS?cid=website_cta_psi";
const STORE_DOWNLOAD =
  "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix?token=ephemeral";
const LAST_MODIFIED = "Wed, 15 Jul 2026 00:00:00 GMT";

function responseWithUrl(body, init, url) {
  const response = new Response(body, init);
  Object.defineProperty(response, "url", { value: url });
  return response;
}

function storePackage(changes = {}) {
  return {
    packagemoniker: "OpenAI.Codex_1.2.3.0_x64__test",
    packagefilename: "OpenAI.Codex_1.2.3.0_x64.Msix",
    packagedownloadurl: STORE_DOWNLOAD,
    packagefilesize: 100,
    ...changes,
  };
}

function fixtureFetch({
  packages = [storePackage()],
  arm64Size = 201,
  x64Size = 202,
  wrapperSize = 203,
} = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const requestUrl = String(url);
    calls.push({ url: requestUrl, init });

    if (requestUrl.startsWith("https://msft-store.tplant.com.au/api/Packages")) {
      return responseWithUrl(
        JSON.stringify(packages),
        { status: 200, headers: { "content-type": "application/json" } },
        requestUrl,
      );
    }

    const directMetadata = new Map([
      [ARM64_ENDPOINT, { etag: '"arm64-v1"', size: arm64Size }],
      [X64_ENDPOINT, { etag: '"x64-v1"', size: x64Size }],
      [WRAPPER_ENDPOINT, { size: wrapperSize }],
    ]);
    const metadata = directMetadata.get(requestUrl);
    if (!metadata) {
      throw new Error(`unexpected fixture URL: ${requestUrl}`);
    }

    const headers = { "content-length": String(metadata.size) };
    if (metadata.etag) headers.etag = metadata.etag;
    if (metadata.lastModified) headers["last-modified"] = metadata.lastModified;
    return responseWithUrl(
      null,
      { status: 200, headers },
      `${new URL(requestUrl).origin}/resolved/${metadata.size}`,
    );
  };
  return { calls, fetchImpl };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "codex-source-test-"));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("ETag is the preferred direct fingerprint", () => {
  assert.equal(
    stableDirectFingerprint({
      etag: '"abc"',
      lastModified: LAST_MODIFIED,
      contentLength: 42,
    }),
    'etag:"abc"|size:42',
  );
});

test("Azure-style hexadecimal ETags remain stable when a proxy removes quotes", () => {
  assert.equal(
    stableDirectFingerprint({
      etag: "0x8DEE17F58782306",
      lastModified: LAST_MODIFIED,
      contentLength: 42,
    }),
    "etag:0x8DEE17F58782306|size:42",
  );
});

test("Last-Modified plus size is the fallback direct fingerprint", () => {
  assert.equal(
    stableDirectFingerprint({
      etag: null,
      lastModified: LAST_MODIFIED,
      contentLength: 42,
    }),
    `last-modified:${LAST_MODIFIED}|size:42`,
  );
});

test("direct fingerprints require a positive safe content length", () => {
  for (const contentLength of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () =>
        stableDirectFingerprint({
          etag: '"abc"',
          lastModified: null,
          contentLength,
        }),
      /stable source identity/,
    );
  }
});

test("direct fingerprints fall back to Last-Modified for unusable ETags", () => {
  for (const etag of ['W/"abc"', "", '""', "unquoted", '"bad value"']) {
    assert.equal(
      stableDirectFingerprint({
        etag,
        lastModified: LAST_MODIFIED,
        contentLength: 42,
      }),
      `last-modified:${LAST_MODIFIED}|size:42`,
    );
  }
});

test("direct fingerprints fail when both ETag and Last-Modified are unusable", () => {
  for (const etag of ['W/"abc"', "", '""', "unquoted", '"bad value"']) {
    assert.throws(
      () =>
        stableDirectFingerprint({
          etag,
          lastModified: "not-a-date",
          contentLength: 42,
        }),
      /stable source identity/,
    );
  }
});

test("direct fingerprints reject missing or invalid Last-Modified fallback", () => {
  for (const lastModified of [
    null,
    "",
    "not-a-date",
    "Wed, 31 Feb 2026 00:00:00 GMT",
    "Tue, 15 Jul 2026 00:00:00 GMT",
  ]) {
    assert.throws(
      () =>
        stableDirectFingerprint({
          etag: null,
          lastModified,
          contentLength: 42,
        }),
      /stable source identity/,
    );
  }
});

test("fetchWithRetry forces redirects and merges the default user agent", async () => {
  let received;
  const fetchImpl = async (_url, init) => {
    received = init;
    return new Response(null, { status: 200 });
  };

  await fetchWithRetry(fetchImpl, "https://example.test/file", {
    redirect: "manual",
    headers: { "x-probe": "yes" },
  });

  assert.equal(received.redirect, "follow");
  assert.equal(received.headers.get("user-agent"), "ding-rs-desktop-mirror/1.0");
  assert.equal(received.headers.get("x-probe"), "yes");
});

test("secure redirect policy rejects HTTPS to HTTP before fetching the target", async () => {
  const calls = [];
  const insecureTarget =
    "http://downloads.example.test/file?token=secret";
  await assert.rejects(
    fetchWithRetry(
      async (url, init) => {
        calls.push({ url: String(url), init });
        if (init.redirect === "follow") {
          calls.push({ url: insecureTarget, init });
          return responseWithUrl(null, { status: 204 }, insecureTarget);
        }
        return responseWithUrl(
          null,
          {
            status: 302,
            headers: { location: insecureTarget },
          },
          String(url),
        );
      },
      "https://downloads.example.test/start?token=initial",
      { method: "HEAD" },
      1,
      {
        allowedRedirectProtocols: ["https:"],
        backoffBaseMs: 0,
      },
    ),
    (error) => {
      assert.match(error.message, /redirect|protocol|HTTPS/i);
      assert.doesNotMatch(inspect(error), /token|secret|\?/i);
      return true;
    },
  );

  assert.deepEqual(calls.map(({ url }) => url), [
    "https://downloads.example.test/start?token=initial",
  ]);
  assert.equal(calls[0].init.redirect, "manual");
  assert.equal(calls[0].init.method, "HEAD");
});

test("secure redirect policy rejects unsafe initial URLs without fetching", async () => {
  let calls = 0;
  await assert.rejects(
    fetchWithRetry(
      async () => {
        calls += 1;
        return new Response(null, { status: 204 });
      },
      "http://downloads.example.test/file?token=secret",
      {},
      1,
      {
        allowedRedirectProtocols: ["https:"],
        backoffBaseMs: 0,
      },
    ),
    (error) => {
      assert.match(error.message, /protocol|HTTPS/i);
      assert.doesNotMatch(inspect(error), /token|secret|\?/i);
      return true;
    },
  );
  assert.equal(calls, 0);
});

test("secure redirect policy rejects and cancels a nonconforming final response URL", async () => {
  let cancelled = false;
  const response = responseWithUrl(
    new ReadableStream({
      cancel() {
        cancelled = true;
      },
    }),
    { status: 200 },
    "http://downloads.example.test/final?token=secret",
  );

  await assert.rejects(
    fetchWithRetry(
      async () => response,
      "https://downloads.example.test/start?token=initial",
      {},
      1,
      {
        allowedRedirectProtocols: ["https:"],
        backoffBaseMs: 0,
      },
    ),
    (error) => {
      assert.match(error.message, /response URL.*protocol/i);
      assert.doesNotMatch(inspect(error), /token|secret|\?/i);
      return true;
    },
  );
  assert.equal(cancelled, true);
});

test("secure redirect policy rejects missing, invalid, and credentialed locations", async () => {
  const cases = [
    [{}, /location/i],
    [{ location: "http://[?token=secret" }, /location/i],
    [
      {
        location:
          "https://user:password@downloads.example.test/file?token=secret",
      },
      /credentials/i,
    ],
  ];

  for (const [headers, pattern] of cases) {
    const calls = [];
    await assert.rejects(
      fetchWithRetry(
        async (url, init) => {
          calls.push(String(url));
          return responseWithUrl(null, { status: 302, headers }, String(url));
        },
        "https://downloads.example.test/start?token=initial",
        {},
        1,
        {
          allowedRedirectProtocols: ["https:"],
          backoffBaseMs: 0,
        },
      ),
      (error) => {
        assert.match(error.message, pattern);
        assert.doesNotMatch(inspect(error), /password|secret|\?/i);
        return true;
      },
    );
    assert.equal(calls.length, 1);
  }
});

test("secure redirect policy follows relative HTTPS redirects without rewriting methods", async () => {
  for (const method of ["GET", "HEAD"]) {
    const calls = [];
    const response = await fetchWithRetry(
      async (url, init) => {
        calls.push({ url: String(url), init });
        if (calls.length === 1) {
          return responseWithUrl(
            null,
            { status: 302, headers: { location: "/final?token=ephemeral" } },
            String(url),
          );
        }
        return responseWithUrl(null, { status: 204 }, String(url));
      },
      "https://downloads.example.test/start",
      { method },
      1,
      {
        allowedRedirectProtocols: ["https:"],
        backoffBaseMs: 0,
      },
    );

    assert.equal(response.status, 204);
    assert.deepEqual(
      calls.map(({ url }) => url),
      [
        "https://downloads.example.test/start",
        "https://downloads.example.test/final?token=ephemeral",
      ],
    );
    assert.ok(calls.every(({ init }) => init.method === method));
    assert.ok(calls.every(({ init }) => init.redirect === "manual"));
  }
});

test("secure redirect policy caps loops at the default five redirects", async () => {
  const calls = [];
  await assert.rejects(
    fetchWithRetry(
      async (url) => {
        calls.push(String(url));
        return responseWithUrl(
          null,
          { status: 302, headers: { location: "/loop" } },
          String(url),
        );
      },
      "https://downloads.example.test/loop",
      { method: "HEAD" },
      1,
      {
        allowedRedirectProtocols: ["https:"],
        backoffBaseMs: 0,
      },
    ),
    /too many redirects|redirect limit/i,
  );
  assert.equal(calls.length, 6);
});

test("external abort remains connected across a secure redirect chain", async () => {
  const controller = new AbortController();
  let abortTimer;
  let calls = 0;
  try {
    abortTimer = setTimeout(() => controller.abort(), 20);
    await assert.rejects(
      fetchWithRetry(
        async (url) => {
          calls += 1;
          if (calls === 1) {
            return responseWithUrl(
              null,
              { status: 302, headers: { location: "/pending" } },
              String(url),
            );
          }
          return new Promise(() => {});
        },
        "https://downloads.example.test/start",
        { signal: controller.signal },
        1,
        {
          allowedRedirectProtocols: ["https:"],
          backoffBaseMs: 0,
          headerTimeoutMs: 100,
        },
      ),
      (error) => {
        assert.equal(error.code, "ABORT_ERR");
        return true;
      },
    );
  } finally {
    clearTimeout(abortTimer);
  }
  assert.equal(calls, 2);
});

test("best-effort body cancellation cannot hang fetchWithRetry", async () => {
  let watchdogTimer;
  const watchdog = new Promise((_, reject) => {
    watchdogTimer = setTimeout(
      () => reject(new Error("cancel watchdog expired")),
      200,
    );
  });
  try {
    await assert.rejects(
      Promise.race([
        fetchWithRetry(
          async () => ({
            ok: false,
            status: 404,
            body: { cancel: () => new Promise(() => {}) },
          }),
          "https://example.test/file?token=secret",
          {},
          1,
          { backoffBaseMs: 0, headerTimeoutMs: 20 },
        ),
        watchdog,
      ]),
      (error) => {
        assert.equal(error.code, "HTTP_404");
        assert.doesNotMatch(inspect(error), /token|secret|\?/i);
        return true;
      },
    );
  } finally {
    clearTimeout(watchdogTimer);
  }
});

test("fetchWithRetry allows the caller to override the user agent", async () => {
  let received;
  const fetchImpl = async (_url, init) => {
    received = init;
    return new Response(null, { status: 200 });
  };

  await fetchWithRetry(fetchImpl, "https://example.test/file", {
    headers: new Headers({ "user-agent": "custom-agent", accept: "text/plain" }),
  });

  assert.equal(received.headers.get("user-agent"), "custom-agent");
  assert.equal(received.headers.get("accept"), "text/plain");
});

test("fetchWithRetry retries failures and returns the later response", async () => {
  let callCount = 0;
  const response = await fetchWithRetry(
    async () => {
      callCount += 1;
      if (callCount === 1) return new Response(null, { status: 503 });
      return new Response(null, { status: 204 });
    },
    "https://example.test/file",
    {},
    2,
    { backoffBaseMs: 0 },
  );

  assert.equal(response.status, 204);
  assert.equal(callCount, 2);
});

test("fetchWithRetry cancels a 404 body and does not retry", async () => {
  let calls = 0;
  let cancellations = 0;
  await assert.rejects(
    fetchWithRetry(
      async () => {
        calls += 1;
        return {
          ok: false,
          status: 404,
          body: {
            async cancel() {
              cancellations += 1;
              throw new Error("cancel failed with token=secret");
            },
          },
        };
      },
      "https://example.test/file?secret=redacted",
      {},
      3,
      { backoffBaseMs: 0 },
    ),
    (error) => {
      assert.match(error.message, /HTTP 404.*example\.test\/file/);
      assert.doesNotMatch(inspect(error), /token=secret/);
      return true;
    },
  );
  assert.equal(calls, 1);
  assert.equal(cancellations, 1);
});

test("fetchWithRetry cancels retryable error bodies before retrying", async () => {
  let calls = 0;
  let cancellations = 0;
  const response = await fetchWithRetry(
    async () => {
      calls += 1;
      if (calls === 1) {
        return {
          ok: false,
          status: 503,
          body: {
            async cancel() {
              cancellations += 1;
            },
          },
        };
      }
      return new Response(null, { status: 204 });
    },
    "https://example.test/file",
    {},
    2,
    { backoffBaseMs: 0 },
  );

  assert.equal(response.status, 204);
  assert.equal(calls, 2);
  assert.equal(cancellations, 1);
});

test("fetchWithRetry sanitizes URL secrets from underlying fetch errors", async () => {
  await assert.rejects(
    fetchWithRetry(
      async () => {
        throw new Error(
          "network failed for https://example.test/file?secret=topsecret#frag",
        );
      },
      "https://example.test/file?secret=topsecret#frag",
      {},
      1,
    ),
    (error) => {
      assert.match(error.message, /request failed.*https:\/\/example\.test\/file/i);
      assert.doesNotMatch(error.message, /secret|topsecret|\?|#frag/i);
      assert.equal(Object.hasOwn(error, "cause"), false);
      return true;
    },
  );
});

test("fetchWithRetry rejects invalid attempt counts before fetching", async () => {
  for (const attempts of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    let called = false;
    await assert.rejects(
      fetchWithRetry(
        async () => {
          called = true;
          return new Response(null, { status: 200 });
        },
        "https://example.test/file",
        {},
        attempts,
      ),
      /attempts.*positive integer/,
    );
    assert.equal(called, false);
  }
});

test("fetchWithRetry enforces a per-attempt header timeout", async () => {
  let calls = 0;
  await assert.rejects(
    fetchWithRetry(
      async (_url, init) => {
        calls += 1;
        return await new Promise((_resolve, reject) => {
          init.signal.addEventListener(
            "abort",
            () => reject(init.signal.reason),
            { once: true },
          );
        });
      },
      "https://example.test/file?token=secret",
      {},
      1,
      { headerTimeoutMs: 20, backoffBaseMs: 0 },
    ),
    (error) => {
      assert.equal(error.code, "ETIMEDOUT");
      assert.doesNotMatch(inspect(error), /token=secret/);
      return true;
    },
  );
  assert.equal(calls, 1);
});

test("fetchWithRetry stops retrying when the external signal aborts", async () => {
  const controller = new AbortController();
  let calls = 0;
  await assert.rejects(
    fetchWithRetry(
      async () => {
        calls += 1;
        controller.abort(new Error("external secret"));
        throw new Error("network secret");
      },
      "https://example.test/file?token=secret",
      { signal: controller.signal },
      3,
      { headerTimeoutMs: 100, backoffBaseMs: 20 },
    ),
    (error) => {
      assert.equal(error.code, "ABORT_ERR");
      assert.doesNotMatch(inspect(error), /secret|\?/i);
      return true;
    },
  );
  assert.equal(calls, 1);
});

test("external abort remains connected after response headers arrive", async () => {
  const controller = new AbortController();
  let receivedSignal;

  await fetchWithRetry(
    async (_url, init) => {
      receivedSignal = init.signal;
      return new Response(null, { status: 200 });
    },
    "https://example.test/file",
    { signal: controller.signal },
    1,
    { headerTimeoutMs: 20, backoffBaseMs: 0 },
  );

  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(receivedSignal.aborted, false);
  controller.abort();
  assert.equal(receivedSignal.aborted, true);
});

test("fetchWithRetry cancels a response that arrives after its header deadline", async () => {
  let cancelled = false;

  await assert.rejects(
    fetchWithRetry(
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return {
          ok: true,
          status: 200,
          body: {
            async cancel() {
              cancelled = true;
            },
          },
        };
      },
      "https://example.test/file?token=secret",
      {},
      1,
      { headerTimeoutMs: 10, backoffBaseMs: 0 },
    ),
    (error) => {
      assert.equal(error.code, "ETIMEDOUT");
      assert.doesNotMatch(inspect(error), /token=secret|\?/);
      return true;
    },
  );

  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(cancelled, true);
});

test("fetchJsonWithRetry applies an absolute body deadline and cancels a stall", async () => {
  let cancelled = false;
  let fallbackTimer;
  try {
    await assert.rejects(
      fetchJsonWithRetry(
        async () =>
          new Response(
            new ReadableStream({
              start(controller) {
                fallbackTimer = setTimeout(() => controller.close(), 150);
              },
              cancel() {
                cancelled = true;
                clearTimeout(fallbackTimer);
              },
            }),
            { status: 200 },
          ),
        "https://example.test/metadata?token=secret",
        {},
        1,
        {
          headerTimeoutMs: 100,
          bodyTimeoutMs: 20,
          backoffBaseMs: 0,
          maxBytes: 1024,
        },
      ),
      (error) => {
        assert.equal(error.code, "ETIMEDOUT");
        assert.doesNotMatch(inspect(error), /token=secret|\?/);
        return true;
      },
    );
  } finally {
    clearTimeout(fallbackTimer);
  }
  assert.equal(cancelled, true);
});

test("fetchJsonWithRetry absolute deadline beats a slow byte drip", async () => {
  let cancelled = false;
  let interval;
  try {
    await assert.rejects(
      fetchJsonWithRetry(
        async () =>
          new Response(
            new ReadableStream({
              start(controller) {
                interval = setInterval(() => controller.enqueue(Uint8Array.of(32)), 5);
              },
              cancel() {
                cancelled = true;
                clearInterval(interval);
              },
            }),
            { status: 200 },
          ),
        "https://example.test/metadata",
        {},
        1,
        {
          headerTimeoutMs: 100,
          bodyTimeoutMs: 25,
          backoffBaseMs: 0,
          maxBytes: 1024,
        },
      ),
      (error) => {
        assert.equal(error.code, "ETIMEDOUT");
        return true;
      },
    );
  } finally {
    clearInterval(interval);
  }
  assert.equal(cancelled, true);
});

test("fetchJsonWithRetry rejects metadata above its byte cap", async () => {
  await assert.rejects(
    fetchJsonWithRetry(
      async () => new Response("123456789", { status: 200 }),
      "https://example.test/metadata?token=secret",
      {},
      1,
      {
        headerTimeoutMs: 100,
        bodyTimeoutMs: 100,
        backoffBaseMs: 0,
        maxBytes: 8,
      },
    ),
    (error) => {
      assert.equal(error.code, "METADATA_TOO_LARGE");
      assert.doesNotMatch(inspect(error), /token=secret|\?/);
      return true;
    },
  );
});

test("fetchJsonWithRetry retries invalid JSON as a complete new attempt", async () => {
  let calls = 0;
  const value = await fetchJsonWithRetry(
    async () => {
      calls += 1;
      return new Response(calls === 1 ? "{invalid" : '{"ok":true}', {
        status: 200,
      });
    },
    "https://example.test/metadata",
    {},
    2,
    {
      headerTimeoutMs: 100,
      bodyTimeoutMs: 100,
      backoffBaseMs: 0,
      maxBytes: 1024,
    },
  );

  assert.deepEqual(value, { ok: true });
  assert.equal(calls, 2);
});

test("fetchJsonWithRetry sanitizes body stream errors", async () => {
  await assert.rejects(
    fetchJsonWithRetry(
      async () =>
        new Response(
          new ReadableStream({
            pull(controller) {
              controller.error(
                new Error("stream token https://signed.test/file?secret=yes"),
              );
            },
          }),
          { status: 200 },
        ),
      "https://example.test/metadata?token=secret",
      {},
      1,
      {
        headerTimeoutMs: 100,
        bodyTimeoutMs: 100,
        backoffBaseMs: 0,
        maxBytes: 1024,
      },
    ),
    (error) => {
      assert.equal(error.code, "METADATA_BODY_ERROR");
      assert.doesNotMatch(inspect(error), /token|secret|signed|\?/i);
      assert.equal(Object.hasOwn(error, "cause"), false);
      return true;
    },
  );
});

test("fetchJsonWithRetry honors external abort without retrying", async () => {
  const controller = new AbortController();
  let calls = 0;
  let cancelled = false;
  let fallbackTimer;
  const abortTimer = setTimeout(() => controller.abort(), 15);
  try {
    await assert.rejects(
      fetchJsonWithRetry(
        async () => {
          calls += 1;
          return new Response(
            new ReadableStream({
              start(streamController) {
                fallbackTimer = setTimeout(() => streamController.close(), 150);
              },
              cancel() {
                cancelled = true;
                clearTimeout(fallbackTimer);
              },
            }),
            { status: 200 },
          );
        },
        "https://example.test/metadata?token=secret",
        { signal: controller.signal },
        3,
        {
          headerTimeoutMs: 100,
          bodyTimeoutMs: 100,
          backoffBaseMs: 0,
          maxBytes: 1024,
        },
      ),
      (error) => {
        assert.equal(error.code, "ABORT_ERR");
        assert.doesNotMatch(inspect(error), /token=secret|\?/);
        return true;
      },
    );
  } finally {
    clearTimeout(abortTimer);
    clearTimeout(fallbackTimer);
  }
  assert.equal(calls, 1);
  assert.equal(cancelled, true);
});

test("downloadAndHash streams bytes to a new file and returns size and SHA256", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    const bytes = Buffer.from("small streamed fixture");

    const result = await downloadAndHash(
      async () => new Response(bytes, { status: 200 }),
      "https://example.test/asset.bin",
      destination,
    );

    assert.deepEqual(result, {
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    assert.deepEqual(await readFile(destination), bytes);
  });
});

test("downloadAndHash never overwrites or removes an existing destination", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    await writeFile(destination, "keep me");
    let calls = 0;

    await assert.rejects(
      downloadAndHash(
        async () => {
          calls += 1;
          return new Response("replacement", { status: 200 });
        },
        "https://example.test/asset.bin?token=secret",
        destination,
        { attempts: 3, backoffBaseMs: 0 },
      ),
      (error) => {
        assert.equal(error.code, "EEXIST");
        assert.doesNotMatch(inspect(error), /token=secret|\?/);
        return true;
      },
    );
    assert.equal(calls, 1);
    assert.equal(await readFile(destination, "utf8"), "keep me");
  });
});

test("downloadAndHash rejects a response without a body", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    await assert.rejects(
      downloadAndHash(
        async () => new Response(null, { status: 200 }),
        "https://example.test/asset.bin",
        destination,
        { attempts: 1, backoffBaseMs: 0 },
      ),
      /empty response body/,
    );
  });
});

test("downloadAndHash rejects an empty stream and cleans its new file", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    await assert.rejects(
      downloadAndHash(
        async () => new Response(new Uint8Array(), { status: 200 }),
        "https://example.test/asset.bin",
        destination,
        { attempts: 1, backoffBaseMs: 0 },
      ),
      /empty downloaded file/,
    );
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("downloadAndHash rejects an advertised size at the exclusive limit", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    let cancellations = 0;

    await assert.rejects(
      downloadAndHash(
        async () => ({
          ok: true,
          status: 200,
          headers: new Headers({ "content-length": "8" }),
          body: {
            async cancel() {
              cancellations += 1;
            },
          },
        }),
        "https://example.test/asset.bin",
        destination,
        { attempts: 1, backoffBaseMs: 0, maxBytes: 8 },
      ),
      /less than.*8|size limit/i,
    );
    assert.equal(cancellations, 1);
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("downloadAndHash maxBytes override may only tighten the shared limit", async () => {
  let calls = 0;
  await assert.rejects(
    downloadAndHash(
      async () => {
        calls += 1;
        return new Response("unused", { status: 200 });
      },
      "https://example.test/asset.bin",
      "/tmp/must-not-be-created.bin",
      { maxBytes: MAX_ASSET_SIZE + 1 },
    ),
    /maxBytes.*no greater|shared.*limit/i,
  );
  assert.equal(calls, 0);
});

test("downloadAndHash enforces the exclusive limit while streaming", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    await assert.rejects(
      downloadAndHash(
        async () => new Response(Buffer.from("12345678"), { status: 200 }),
        "https://example.test/asset.bin",
        destination,
        { attempts: 1, backoffBaseMs: 0, maxBytes: 8 },
      ),
      /less than.*8|size limit/i,
    );
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("downloadAndHash retries a transient mid-stream failure from scratch", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    const successBytes = Buffer.from("complete retry");
    let calls = 0;

    const result = await downloadAndHash(
      async () => {
        calls += 1;
        if (calls === 1) {
          let pulls = 0;
          return new Response(
            new ReadableStream({
              pull(controller) {
                pulls += 1;
                if (pulls === 1) controller.enqueue(Uint8Array.of(1, 2, 3));
                else controller.error(new Error("transient stream failure"));
              },
            }),
            { status: 200 },
          );
        }
        return new Response(successBytes, { status: 200 });
      },
      "https://example.test/asset.bin",
      destination,
      { attempts: 2, backoffBaseMs: 0, inactivityTimeoutMs: 100 },
    );

    assert.equal(calls, 2);
    assert.deepEqual(await readFile(destination), successBytes);
    assert.deepEqual(result, {
      size: successBytes.length,
      sha256: createHash("sha256").update(successBytes).digest("hex"),
    });
  });
});

test("downloadAndHash sanitizes stream errors and removes partial files", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    let pulls = 0;
    const secret = "https://signed.test/file?token=topsecret";

    await assert.rejects(
      downloadAndHash(
        async () =>
          new Response(
            new ReadableStream({
              pull(controller) {
                pulls += 1;
                if (pulls === 1) controller.enqueue(Uint8Array.of(1, 2, 3));
                else controller.error(new Error(`stream failed for ${secret}`));
              },
            }),
            { status: 200 },
          ),
        `${secret}#fragment`,
        destination,
        { attempts: 1, backoffBaseMs: 0, inactivityTimeoutMs: 100 },
      ),
      (error) => {
        assert.match(error.message, /download failed.*https:\/\/signed\.test\/file/i);
        assert.doesNotMatch(inspect(error), /token|topsecret|\?|fragment/i);
        assert.equal(Object.hasOwn(error, "cause"), false);
        return true;
      },
    );
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("downloadAndHash aborts an inactive response body and cleans partial data", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    let cancelled = false;
    let fallbackTimer;

    await assert.rejects(
      downloadAndHash(
        async () =>
          new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(Uint8Array.of(1));
                fallbackTimer = setTimeout(() => controller.close(), 150);
              },
              cancel() {
                cancelled = true;
                clearTimeout(fallbackTimer);
              },
            }),
            { status: 200 },
          ),
        "https://example.test/asset.bin",
        destination,
        { attempts: 1, backoffBaseMs: 0, inactivityTimeoutMs: 20 },
      ),
      (error) => {
        assert.equal(error.code, "ETIMEDOUT");
        return true;
      },
    );
    clearTimeout(fallbackTimer);
    assert.equal(cancelled, true);
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("download body can outlive its short header deadline while staying active", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    const bytes = Uint8Array.of(7, 8, 9);

    const result = await downloadAndHash(
      async () =>
        new Response(
          new ReadableStream({
            async pull(controller) {
              await new Promise((resolve) => setTimeout(resolve, 30));
              controller.enqueue(bytes);
              controller.close();
            },
          }),
          { status: 200 },
        ),
      "https://example.test/asset.bin",
      destination,
      {
        attempts: 1,
        backoffBaseMs: 0,
        headerTimeoutMs: 10,
        inactivityTimeoutMs: 100,
      },
    );

    assert.equal(result.size, bytes.length);
    assert.deepEqual(await readFile(destination), Buffer.from(bytes));
  });
});

test("downloadAndHash aborts an active body when its external signal aborts", async () => {
  await withTempDir(async (directory) => {
    const destination = join(directory, "asset.bin");
    const controller = new AbortController();
    let cancelled = false;
    let fallbackTimer;
    const abortTimer = setTimeout(() => controller.abort(), 20);

    try {
      await assert.rejects(
        downloadAndHash(
          async () =>
            new Response(
              new ReadableStream({
                start(streamController) {
                  streamController.enqueue(Uint8Array.of(1));
                  fallbackTimer = setTimeout(
                    () => streamController.close(),
                    150,
                  );
                },
                cancel() {
                  cancelled = true;
                  clearTimeout(fallbackTimer);
                },
              }),
              { status: 200 },
            ),
          "https://example.test/asset.bin?token=secret",
          destination,
          {
            attempts: 3,
            backoffBaseMs: 0,
            inactivityTimeoutMs: 100,
            signal: controller.signal,
          },
        ),
        (error) => {
          assert.equal(error.code, "ABORT_ERR");
          assert.doesNotMatch(inspect(error), /token=secret|\?/);
          return true;
        },
      );
    } finally {
      clearTimeout(abortTimer);
      clearTimeout(fallbackTimer);
    }
    assert.equal(cancelled, true);
    await assert.rejects(stat(destination), /ENOENT/);
  });
});

test("Codex probes return the fixed four-asset contract", async () => {
  const { fetchImpl } = fixtureFetch();

  const assets = await probeCodexAssets(fetchImpl);

  assert.deepEqual(assets, [
    {
      id: "darwin-arm64-dmg",
      filename: "Codex-macOS-arm64.dmg",
      sourceEndpoint: ARM64_ENDPOINT,
      sourceFingerprint: 'etag:"arm64-v1"|size:201',
      resolvedUrl: "https://persistent.oaistatic.com/resolved/201",
      expectedSize: 201,
    },
    {
      id: "darwin-x64-dmg",
      filename: "Codex-macOS-x64.dmg",
      sourceEndpoint: X64_ENDPOINT,
      sourceFingerprint: 'etag:"x64-v1"|size:202',
      resolvedUrl: "https://persistent.oaistatic.com/resolved/202",
      expectedSize: 202,
    },
    {
      id: "win32-x64-msix",
      filename: "Codex-Windows-x64.msix",
      sourceEndpoint: STORE_ENDPOINT,
      sourceFingerprint:
        "moniker:OpenAI.Codex_1.2.3.0_x64__test|file:OpenAI.Codex_1.2.3.0_x64.Msix|size:100",
      resolvedUrl: STORE_DOWNLOAD,
      expectedSize: 100,
    },
    {
      id: "win32-x64-installer",
      filename: "Codex-Windows-Installer.exe",
      sourceEndpoint: WRAPPER_ENDPOINT,
      sourceFingerprint:
        "store-moniker:OpenAI.Codex_1.2.3.0_x64__test|" +
        "store-file:OpenAI.Codex_1.2.3.0_x64.Msix|" +
        "store-size:100|wrapper-size:203",
      resolvedUrl: "https://get.microsoft.com/resolved/203",
      expectedSize: 203,
    },
  ]);
});

test("wrapper identity changes with every Store identity field and wrapper size", async () => {
  const baseline = (await probeCodexAssets(fixtureFetch().fetchImpl))[3]
    .sourceFingerprint;
  const variants = [
    fixtureFetch({
      packages: [
        storePackage({ packagemoniker: "OpenAI.Codex_1.2.4.0_x64__test" }),
      ],
    }),
    fixtureFetch({
      packages: [
        storePackage({ packagefilename: "OpenAI.Codex_1.2.4.0_x64.Msix" }),
      ],
    }),
    fixtureFetch({
      packages: [storePackage({ packagefilesize: 101 })],
    }),
    fixtureFetch({ wrapperSize: 204 }),
  ];

  for (const { fetchImpl } of variants) {
    const fingerprint = (await probeCodexAssets(fetchImpl))[3]
      .sourceFingerprint;
    assert.notEqual(fingerprint, baseline);
  }
});

test("Codex probes use one metadata GET and three bodyless HEAD requests with the mirror UA", async () => {
  const { calls, fetchImpl } = fixtureFetch();

  await probeCodexAssets(fetchImpl, { probeTimeoutMs: 100 });

  assert.equal(calls.length, 4);
  assert.equal(calls[0].url, STORE_ENDPOINT);
  assert.deepEqual(calls.map(({ init }) => init.method), [
    "GET",
    "HEAD",
    "HEAD",
    "HEAD",
  ]);
  assert.equal(calls.some(({ url }) => url === STORE_DOWNLOAD), false);
  assert.equal(calls.some(({ url }) => url.startsWith("http://")), false);
  assert.ok(calls.every(({ init }) => init.redirect === "manual"));
  assert.ok(calls.every(({ url }) => new URL(url).protocol === "https:"));
  assert.ok(calls.every(({ init }) => init.signal instanceof AbortSignal));
  assert.ok(
    calls.every(
      ({ init }) =>
        init.headers.get("user-agent") === "ding-rs-desktop-mirror/1.0",
    ),
  );
});

test("Codex metadata probe rejects an HTTPS to HTTP redirect without fetching it", async () => {
  const calls = [];
  await assert.rejects(
    probeCodexAssets(
      async (url, init) => {
        calls.push({ url: String(url), init });
        if (init.redirect === "follow") {
          const insecureTarget =
            "http://metadata.example.test/packages?token=ephemeral";
          calls.push({ url: insecureTarget, init });
          return responseWithUrl(
            JSON.stringify([storePackage()]),
            { status: 200 },
            insecureTarget,
          );
        }
        return responseWithUrl(
          null,
          {
            status: 302,
            headers: {
              location:
                "http://metadata.example.test/packages?token=ephemeral",
            },
          },
          String(url),
        );
      },
      { attempts: 1, backoffBaseMs: 0, probeTimeoutMs: 100 },
    ),
    /redirect|protocol|HTTPS/i,
  );
  assert.deepEqual(calls.map(({ url }) => url), [STORE_ENDPOINT]);
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.redirect, "manual");
});

test("Store package selection ignores unrelated entries instead of taking the first item", async () => {
  const { fetchImpl } = fixtureFetch({
    packages: [
      {
        packagemoniker: "Microsoft.VCLibs_14.0_x64__test",
        packagefilename: "Microsoft.VCLibs.appx",
        packagedownloadurl: "not a URL",
        packagefilesize: 0,
      },
      storePackage(),
    ],
  });

  const assets = await probeCodexAssets(fetchImpl);
  assert.match(
    assets[2].sourceFingerprint,
    /^moniker:OpenAI\.Codex_1\.2\.3\.0_x64__test\|/,
  );
});

test("Store package size accepts a canonicalizable positive decimal string", async () => {
  const { fetchImpl } = fixtureFetch({
    packages: [storePackage({ packagefilesize: "100" })],
  });

  const assets = await probeCodexAssets(fetchImpl);
  assert.match(assets[2].sourceFingerprint, /\|size:100$/);
  assert.equal(assets[2].expectedSize, 100);
});

test("Store package selection rejects malformed matching candidates", async () => {
  const cases = [
    [
      storePackage({ packagemoniker: 42 }),
      /matching.*Codex.*MSIX|moniker/i,
    ],
    [
      storePackage({ packagefilename: 42 }),
      /matching.*Codex.*MSIX|filename/i,
    ],
    [storePackage({ packagedownloadurl: "" }), /download URL/i],
    [storePackage({ packagedownloadurl: "file:///tmp/Codex.msix" }), /download URL/i],
    [storePackage({ packagefilesize: 0 }), /package size/i],
    [storePackage({ packagefilesize: "1.5" }), /package size/i],
    [
      storePackage({ packagefilesize: String(Number.MAX_SAFE_INTEGER + 1) }),
      /package size/i,
    ],
  ];

  for (const [candidate, pattern] of cases) {
    const { fetchImpl } = fixtureFetch({ packages: [candidate] });
    await assert.rejects(probeCodexAssets(fetchImpl), pattern);
  }
});

test("Store package selection fails closed when distinct candidates are ambiguous", async () => {
  const packages = [
    storePackage(),
    storePackage({
      packagemoniker: "OpenAI.Codex_1.2.4.0_x64__test",
      packagefilename: "OpenAI.Codex_1.2.4.0_x64.Msix",
      packagedownloadurl:
        "https://alt.dl.delivery.mp.microsoft.com/Codex-new.msix",
      packagefilesize: 101,
    }),
  ];

  for (const orderedPackages of [packages, [...packages].reverse()]) {
    const { fetchImpl } = fixtureFetch({ packages: orderedPackages });
    await assert.rejects(probeCodexAssets(fetchImpl), /ambiguous.*Codex MSIX/i);
  }
});

test("Store package selection ignores non-x64 Codex packages", async () => {
  const arm64 = storePackage({
    packagemoniker: "OpenAI.Codex_1.2.3.0_arm64__test",
    packagefilename: "OpenAI.Codex_1.2.3.0_arm64.Msix",
    packagedownloadurl:
      "https://arm.dl.delivery.mp.microsoft.com/Codex-arm64.msix",
  });
  const x86 = storePackage({
    packagemoniker: "OpenAI.Codex_1.2.3.0_x86__test",
    packagefilename: "OpenAI.Codex_1.2.3.0_x86.Msix",
    packagedownloadurl:
      "https://x86.dl.delivery.mp.microsoft.com/Codex-x86.msix",
  });
  const { fetchImpl } = fixtureFetch({
    packages: [arm64, x86, storePackage()],
  });

  const assets = await probeCodexAssets(fetchImpl);
  assert.match(assets[2].sourceFingerprint, /_x64__/);
  assert.doesNotMatch(assets[2].sourceFingerprint, /arm64/i);
});

test("Store package selection fails when metadata has no x64 Codex package", async () => {
  const arm64 = storePackage({
    packagemoniker: "OpenAI.Codex_1.2.3.0_arm64__test",
    packagefilename: "OpenAI.Codex_1.2.3.0_arm64.Msix",
    packagedownloadurl:
      "https://arm.dl.delivery.mp.microsoft.com/Codex-arm64.msix",
  });
  const { fetchImpl } = fixtureFetch({ packages: [arm64] });

  await assert.rejects(probeCodexAssets(fetchImpl), /no matching.*x64|x64.*MSIX/i);
});

test("Store package URL must use the reviewed Microsoft delivery suffix", async () => {
  for (const packagedownloadurl of [
    "https://delivery.mp.microsoft.com.evil.test/Codex.msix",
    "https://unreviewed.example.test/Codex.msix",
  ]) {
    const { fetchImpl } = fixtureFetch({
      packages: [storePackage({ packagedownloadurl })],
    });
    await assert.rejects(
      probeCodexAssets(fetchImpl),
      /Microsoft delivery host/i,
    );
  }
});

test("Store package URL accepts the reviewed root and subdomain hosts", async () => {
  for (const packagedownloadurl of [
    "https://delivery.mp.microsoft.com/Codex.msix",
    STORE_DOWNLOAD,
  ]) {
    const { fetchImpl } = fixtureFetch({
      packages: [storePackage({ packagedownloadurl })],
    });
    const assets = await probeCodexAssets(fetchImpl);
    assert.equal(assets[2].id, "win32-x64-msix");
  }
});

test("Store package retains an approved HTTP URL as metadata without fetching it", async () => {
  const initialUrl =
    "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix?token=ephemeral";
  const { calls, fetchImpl } = fixtureFetch({
    packages: [storePackage({ packagedownloadurl: initialUrl })],
  });

  const assets = await probeCodexAssets(fetchImpl);
  assert.equal(assets[2].resolvedUrl, initialUrl);
  assert.equal(assets[2].expectedSize, 100);
  assert.equal(calls.some(({ url }) => url === initialUrl), false);
  assert.equal(calls.some(({ url }) => url.startsWith("http://")), false);
});

test("Store package URL rejects embedded credentials", async () => {
  const { fetchImpl } = fixtureFetch({
    packages: [
      storePackage({
        packagedownloadurl:
          "https://user:password@tlu.dl.delivery.mp.microsoft.com/Codex.msix",
      }),
    ],
  });

  await assert.rejects(probeCodexAssets(fetchImpl), /credentials/i);
});

test("Store package URL accepts only default HTTP and HTTPS ports", async () => {
  for (const packagedownloadurl of [
    "http://tlu.dl.delivery.mp.microsoft.com:80/Codex.msix",
    "https://tlu.dl.delivery.mp.microsoft.com:443/Codex.msix",
  ]) {
    const { fetchImpl } = fixtureFetch({
      packages: [storePackage({ packagedownloadurl })],
    });
    const assets = await probeCodexAssets(fetchImpl);
    assert.equal(assets[2].expectedSize, 100);
  }

  for (const packagedownloadurl of [
    "http://tlu.dl.delivery.mp.microsoft.com:8080/Codex.msix",
    "https://tlu.dl.delivery.mp.microsoft.com:444/Codex.msix",
  ]) {
    const { fetchImpl } = fixtureFetch({
      packages: [storePackage({ packagedownloadurl })],
    });
    await assert.rejects(probeCodexAssets(fetchImpl), /port/i);
  }
});

test("Store package URL rejects fragments", async () => {
  for (const packagedownloadurl of [
    "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix#fragment",
    "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix#",
    "http://tlu.dl.delivery.mp.microsoft.com/Codex.msix?token=value#",
  ]) {
    const { fetchImpl } = fixtureFetch({
      packages: [storePackage({ packagedownloadurl })],
    });
    await assert.rejects(probeCodexAssets(fetchImpl), /fragment/i);
  }
});

test("Store package selection rejects non-array and empty metadata", async () => {
  for (const packages of [{ packages: [] }, null, {}]) {
    const { fetchImpl } = fixtureFetch({ packages });
    await assert.rejects(
      probeCodexAssets(fetchImpl),
      /Store metadata.*array|no matching Codex MSIX/i,
    );
  }
});

test("direct probes fail closed when HEAD lacks stable metadata", async () => {
  const { fetchImpl: baseFetch } = fixtureFetch();
  const fetchImpl = async (url, init) => {
    if (String(url) === ARM64_ENDPOINT) {
      return responseWithUrl(
        null,
        { status: 200, headers: { "content-length": "201" } },
        String(url),
      );
    }
    return baseFetch(url, init);
  };

  await assert.rejects(probeCodexAssets(fetchImpl), /stable source identity/);
});

test("Codex probes reject direct, Store, and wrapper sizes at 2 GiB", async () => {
  const fixtures = [
    fixtureFetch({ arm64Size: MAX_ASSET_SIZE }),
    fixtureFetch({
      packages: [storePackage({ packagefilesize: MAX_ASSET_SIZE })],
    }),
    fixtureFetch({ wrapperSize: MAX_ASSET_SIZE }),
  ];

  for (const { fetchImpl } of fixtures) {
    await assert.rejects(
      probeCodexAssets(fetchImpl),
      /less than 2 GiB|asset size limit/i,
    );
  }
});

test("Codex probes honor an already-aborted external signal", async () => {
  const controller = new AbortController();
  controller.abort(new Error("external secret"));
  let calls = 0;

  await assert.rejects(
    probeCodexAssets(
      async () => {
        calls += 1;
        throw new Error("must not fetch");
      },
      { signal: controller.signal, probeTimeoutMs: 20 },
    ),
    (error) => {
      assert.equal(error.code, "ABORT_ERR");
      assert.doesNotMatch(inspect(error), /secret/);
      return true;
    },
  );
  assert.equal(calls, 0);
});

test("Codex probe timeout also bounds the Store metadata body", async () => {
  let cancelled = false;
  let fallbackTimer;
  try {
    await assert.rejects(
      probeCodexAssets(
        async () =>
          new Response(
            new ReadableStream({
              start(controller) {
                fallbackTimer = setTimeout(() => controller.close(), 150);
              },
              cancel() {
                cancelled = true;
                clearTimeout(fallbackTimer);
              },
            }),
            { status: 200 },
          ),
        { attempts: 1, backoffBaseMs: 0, probeTimeoutMs: 20 },
      ),
      (error) => {
        assert.equal(error.code, "ETIMEDOUT");
        return true;
      },
    );
  } finally {
    clearTimeout(fallbackTimer);
  }
  assert.equal(cancelled, true);
});

function stagingProbe(id, changes = {}) {
  const definitions = {
    "darwin-arm64-dmg": {
      filename: "Codex-macOS-arm64.dmg",
      sourceEndpoint: ARM64_ENDPOINT,
      resolvedUrl: ARM64_ENDPOINT,
      sourceFingerprint: 'etag:"stage"|size:12',
      expectedSize: 12,
    },
    "darwin-x64-dmg": {
      filename: "Codex-macOS-x64.dmg",
      sourceEndpoint: X64_ENDPOINT,
      resolvedUrl: X64_ENDPOINT,
      sourceFingerprint: 'etag:"stage"|size:12',
      expectedSize: 12,
    },
    "win32-x64-msix": {
      filename: "Codex-Windows-x64.msix",
      sourceEndpoint: STORE_ENDPOINT,
      resolvedUrl: STORE_DOWNLOAD,
      expectedSize: 12,
    },
    "win32-x64-installer": {
      filename: "Codex-Windows-Installer.exe",
      sourceEndpoint: WRAPPER_ENDPOINT,
      resolvedUrl: WRAPPER_ENDPOINT,
      expectedSize: 12,
    },
  };
  return {
    id,
    sourceFingerprint: `staging:${id}`,
    ...definitions[id],
    ...changes,
  };
}

function binaryFetch(bytes, finalUrl) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const headers = { "content-length": String(bytes.length) };
    if (new URL(finalUrl).hostname === "persistent.oaistatic.com") {
      headers.etag = '"stage"';
    }
    return responseWithUrl(
      bytes,
      { status: 200, headers },
      finalUrl,
    );
  };
  return { calls, fetchImpl };
}

test("Microsoft delivery final URL validation accepts only reviewed root and subdomains", () => {
  for (const url of [
    "http://delivery.mp.microsoft.com/Codex.msix?token=ephemeral",
    "https://tlu.dl.delivery.mp.microsoft.com/Codex.msix",
  ]) {
    assert.doesNotThrow(() => assertMicrosoftDeliveryUrl(url));
  }

  for (const url of [
    "https://delivery.mp.microsoft.com.example.test/Codex.msix?token=secret",
    "https://evildelivery.mp.microsoft.com.example/Codex.msix",
    "https://user:pass@delivery.mp.microsoft.com/Codex.msix",
    "https://delivery.mp.microsoft.com:444/Codex.msix",
    "https://delivery.mp.microsoft.com/Codex.msix#fragment",
    "ftp://delivery.mp.microsoft.com/Codex.msix",
  ]) {
    assert.throws(() => assertMicrosoftDeliveryUrl(url), /Microsoft delivery|credentials|port|fragment|HTTP/i);
  }
});

test("changed MSIX rejects an unreviewed final response before body consumption and without retry", async () => {
  await withTempDir(async (directory) => {
    let fetchCalls = 0;
    let reads = 0;
    let cancellations = 0;
    const source = createCodexSource({
      fetchImpl: async () => {
        fetchCalls += 1;
        return {
          ok: true,
          status: 200,
          headers: new Headers({ "content-length": "3" }),
          url: "https://delivery.mp.microsoft.com.evil.test/Codex.msix?token=secret",
          body: {
            read() {
              reads += 1;
            },
            cancel() {
              cancellations += 1;
            },
          },
        };
      },
      verifyWindowsSignature: async () => assert.fail("signature must not run"),
    });
    const destination = join(directory, "Codex-Windows-x64.msix");
    await assert.rejects(
      source.stageChanged(
        stagingProbe("win32-x64-msix", { expectedSize: 3 }),
        destination,
      ),
      (error) => {
        assert.match(error.message, /response validation|Microsoft delivery/i);
        assert.doesNotMatch(inspect(error), /token=secret|evil\.test/);
        return true;
      },
    );
    assert.equal(fetchCalls, 1);
    assert.equal(reads, 0);
    assert.equal(cancellations, 1);
    await assert.rejects(access(destination));
  });
});

test("changed MSIX requires a valid expectedSize before downloading", async () => {
  await withTempDir(async (directory) => {
    let fetchCalls = 0;
    const source = createCodexSource({
      fetchImpl: async () => {
        fetchCalls += 1;
        return new Response("unexpected");
      },
      verifyWindowsSignature: async () => {},
    });
    for (const expectedSize of [undefined, 0, -1, 1.5, MAX_ASSET_SIZE]) {
      await assert.rejects(
        source.stageChanged(
          stagingProbe("win32-x64-msix", { expectedSize }),
          join(directory, `invalid-${String(expectedSize)}.msix`),
        ),
        /expectedSize|expected size/i,
      );
    }
    assert.equal(fetchCalls, 0);
  });
});

test("changed MSIX enforces metadata size and removes a mismatched staged file", async () => {
  await withTempDir(async (directory) => {
    const bytes = Buffer.from("actual-msix");
    const binary = binaryFetch(bytes, STORE_DOWNLOAD);
    const source = createCodexSource({
      fetchImpl: binary.fetchImpl,
      verifyWindowsSignature: async () => assert.fail("signature must not run"),
    });
    const destination = join(directory, "Codex-Windows-x64.msix");
    await assert.rejects(
      source.stageChanged(
        stagingProbe("win32-x64-msix", { expectedSize: bytes.length + 1 }),
        destination,
      ),
      /size|response validation/i,
    );
    await assert.rejects(access(destination));
  });
});

test("changed MSIX and EXE verify Windows signatures while DMGs do not", async () => {
  await withTempDir(async (directory) => {
    const signatureCalls = [];
    const bytes = Buffer.from("signed-bytes");
    for (const id of [
      "win32-x64-msix",
      "win32-x64-installer",
      "darwin-arm64-dmg",
    ]) {
      const probe = stagingProbe(id, {
        expectedSize: bytes.length,
        ...(id.startsWith("darwin")
          ? { sourceFingerprint: `etag:"stage"|size:${bytes.length}` }
          : {}),
      });
      const finalUrl = id === "win32-x64-msix" ? STORE_DOWNLOAD : probe.resolvedUrl;
      const source = createCodexSource({
        fetchImpl: binaryFetch(bytes, finalUrl).fetchImpl,
        verifyWindowsSignature: async (path) => signatureCalls.push(path),
      });
      const destination = join(directory, probe.filename);
      assert.deepEqual(await source.stageChanged(probe, destination), {
        size: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      });
    }
    assert.deepEqual(signatureCalls.map((path) => basename(path)), [
      "Codex-Windows-x64.msix",
      "Codex-Windows-Installer.exe",
    ]);
  });
});

test("signature verification failure removes downloaded Windows files", async () => {
  await withTempDir(async (directory) => {
    for (const id of ["win32-x64-msix", "win32-x64-installer"]) {
      const bytes = Buffer.from(`unsigned:${id}`);
      const probe = stagingProbe(id, {
        expectedSize: bytes.length,
      });
      const finalUrl = id === "win32-x64-msix" ? STORE_DOWNLOAD : probe.resolvedUrl;
      const source = createCodexSource({
        fetchImpl: binaryFetch(bytes, finalUrl).fetchImpl,
        verifyWindowsSignature: async () => {
          throw new Error("signtool says token=secret");
        },
      });
      const destination = join(directory, probe.filename);
      await assert.rejects(source.stageChanged(probe, destination), (error) => {
        assert.match(error.message, /signature/i);
        assert.doesNotMatch(inspect(error), /token=secret/);
        return true;
      });
      await assert.rejects(access(destination));
    }
  });
});

test("createCodexSource probe delegates to the four-asset probe contract", async () => {
  const fixture = fixtureFetch();
  const source = createCodexSource({
    fetchImpl: fixture.fetchImpl,
    verifyWindowsSignature: async () => {},
  });
  const values = await source.probe();
  assert.deepEqual(values.map((value) => value.id), [
    "darwin-arm64-dmg",
    "darwin-x64-dmg",
    "win32-x64-msix",
    "win32-x64-installer",
  ]);
  assert.deepEqual(values.map((value) => value.expectedSize), [201, 202, 100, 203]);
});

function guardedBinaryResponse({ finalUrl, headers = {} }) {
  let reads = 0;
  let cancellations = 0;
  return {
    response: {
      ok: true,
      status: 200,
      url: finalUrl,
      headers: new Headers(headers),
      body: {
        read() {
          reads += 1;
        },
        cancel() {
          cancellations += 1;
        },
      },
    },
    observations: () => ({ reads, cancellations }),
  };
}

test("changed DMG binds GET to probe fingerprint and official final host before body reads", async () => {
  await withTempDir(async (directory) => {
    for (const [index, responseFixture] of [
      guardedBinaryResponse({
        finalUrl: "https://persistent.oaistatic.com/Codex.dmg",
        headers: { etag: '"different"', "content-length": "3" },
      }),
      guardedBinaryResponse({
        finalUrl: "https://persistent.oaistatic.com.evil.test/Codex.dmg",
        headers: { etag: '"expected"', "content-length": "3" },
      }),
    ].entries()) {
      let calls = 0;
      const source = createCodexSource({
        fetchImpl: async () => {
          calls += 1;
          return responseFixture.response;
        },
        verifyWindowsSignature: async () => assert.fail("DMG must not verify"),
      });
      const destination = join(directory, `dmg-${index}.dmg`);
      await assert.rejects(
        source.stageChanged(
          stagingProbe("darwin-arm64-dmg", {
            expectedSize: 3,
            sourceFingerprint: 'etag:"expected"|size:3',
          }),
          destination,
        ),
        /response validation|fingerprint|host/i,
      );
      assert.equal(calls, 1);
      assert.deepEqual(responseFixture.observations(), {
        reads: 0,
        cancellations: 1,
      });
      await assert.rejects(access(destination));
    }
  });
});

test("changed wrapper rejects final host or size mismatch before body reads", async () => {
  await withTempDir(async (directory) => {
    for (const [index, responseFixture] of [
      guardedBinaryResponse({
        finalUrl: "https://download.get.microsoft.com.evil.test/installer.exe",
        headers: { "content-length": "3" },
      }),
      guardedBinaryResponse({
        finalUrl: "https://get.microsoft.com/installer.exe",
        headers: { "content-length": "4" },
      }),
    ].entries()) {
      let calls = 0;
      const source = createCodexSource({
        fetchImpl: async () => {
          calls += 1;
          return responseFixture.response;
        },
        verifyWindowsSignature: async () => assert.fail("must reject first"),
      });
      const destination = join(directory, `wrapper-${index}.exe`);
      await assert.rejects(
        source.stageChanged(
          stagingProbe("win32-x64-installer", { expectedSize: 3 }),
          destination,
        ),
        /response validation|host|size/i,
      );
      assert.equal(calls, 1);
      assert.deepEqual(responseFixture.observations(), {
        reads: 0,
        cancellations: 1,
      });
      await assert.rejects(access(destination));
    }
  });
});

test("all four changed assets enforce expectedSize and succeed with bound GET metadata", async () => {
  await withTempDir(async (directory) => {
    const bytes = Buffer.from("bound-bytes");
    const signatureCalls = [];
    const cases = [
      ["darwin-arm64-dmg", ARM64_ENDPOINT],
      ["darwin-x64-dmg", X64_ENDPOINT],
      ["win32-x64-msix", STORE_DOWNLOAD],
      ["win32-x64-installer", WRAPPER_ENDPOINT],
    ];
    for (const [id, finalUrl] of cases) {
      const headers = { "content-length": String(bytes.length) };
      const changes = { expectedSize: bytes.length };
      if (id.startsWith("darwin")) {
        headers.etag = '"bound"';
        changes.sourceFingerprint = `etag:"bound"|size:${bytes.length}`;
      }
      const source = createCodexSource({
        fetchImpl: async () =>
          responseWithUrl(bytes, { status: 200, headers }, finalUrl),
        verifyWindowsSignature: async (path) => signatureCalls.push(basename(path)),
      });
      const probe = stagingProbe(id, changes);
      const result = await source.stageChanged(probe, join(directory, probe.filename));
      assert.equal(result.size, bytes.length);
    }
    assert.deepEqual(signatureCalls, [
      "Codex-Windows-x64.msix",
      "Codex-Windows-Installer.exe",
    ]);
  });
});

test("stream size race below expectedSize removes the staged file", async () => {
  await withTempDir(async (directory) => {
    const bytes = Buffer.from("short");
    const source = createCodexSource({
      fetchImpl: async () =>
        responseWithUrl(bytes, { status: 200 }, STORE_DOWNLOAD),
      verifyWindowsSignature: async () => assert.fail("size gate runs first"),
    });
    const destination = join(directory, "race.msix");
    await assert.rejects(
      source.stageChanged(
        stagingProbe("win32-x64-msix", { expectedSize: bytes.length + 1 }),
        destination,
      ),
      /size/i,
    );
    await assert.rejects(access(destination));
  });
});
