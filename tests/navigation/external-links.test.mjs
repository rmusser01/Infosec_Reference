import test from "node:test";
import assert from "node:assert/strict";
import {
  isPublicAddress,
  inspectUrl,
} from "../../tools/navigation/external-links.mjs";
test("rejects private, loopback, link-local, mapped, documentation and reserved addresses", () => {
  for (const address of [
    "127.0.0.1",
    "10.2.3.4",
    "169.254.169.254",
    "100.64.0.1",
    "192.168.1.1",
    "192.0.2.1",
    "::1",
    "fe80::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "2001:db8::1",
  ])
    assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
});
test("revalidates redirects before requests and confirms type from final response", async () => {
  const options = {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async (url) =>
      url.pathname === "/first"
        ? { status: 302, headers: { location: "/download" } }
        : { status: 200, headers: { "content-type": "application/pdf" } },
  };
  const result = await inspectUrl("https://example.org/first", options);
  assert.equal(result.classification.type, "pdf");
  assert.equal(result.finalUrl, "https://example.org/download");
  assert.equal(result.redirectChain.length, 1);
  const blocked = await inspectUrl("https://example.org/first", {
    ...options,
    request: async () => ({
      status: 302,
      headers: { location: "http://127.0.0.1/private" },
    }),
  });
  assert.equal(blocked.availabilityState, "blocked");
});
test("HEAD rejection falls back to bounded GET, retries transient errors and records uncertainty", async () => {
  const methods = [];
  const result = await inspectUrl("https://example.org/file", {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async (url, options) => {
      methods.push(options.method);
      return {
        status: options.method === "HEAD" ? 405 : 200,
        headers: { "content-type": "text/html" },
      };
    },
  });
  assert.deepEqual(methods, ["HEAD", "GET"]);
  assert.equal(result.classification.type, "webpage");
  let attempts = 0;
  const retry = await inspectUrl("https://example.org/", {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async () => {
      attempts++;
      return { status: 429, headers: {} };
    },
  });
  assert.equal(attempts, 2);
  assert.equal(retry.availabilityState, "uncertain");
  const missing = await inspectUrl("https://example.org/", {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async () => ({ status: 404, headers: {} }),
  });
  assert.equal(missing.availabilityState, "missing");
});
test("rejects mixed public/private DNS answers, credentials and redirect loops", async () => {
  const mixed = await inspectUrl("https://example.org/", {
    resolveHost: async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "10.0.0.1", family: 4 },
    ],
    request: async () => {
      throw Error("must not dispatch");
    },
  });
  assert.equal(mixed.availabilityState, "blocked");
  assert.equal(
    (await inspectUrl("https://user:pass@example.org/")).availabilityState,
    "blocked",
  );
  let n = 0;
  const loop = await inspectUrl("https://example.org/", {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async () => {
      n++;
      return { status: 302, headers: { location: "/again" } };
    },
  });
  assert.equal(n, 6);
  assert.equal(loop.availabilityState, "uncertain");
});
test("external reports preserve PDF candidates when the server returns an HTML access-error page", async () => {
  const result = await inspectUrl("https://example.org/report.pdf", {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async () => ({
      status: 403,
      headers: { "content-type": "text/html" },
    }),
  });
  assert.equal(result.availabilityState, "uncertain");
  assert.equal(result.classification.type, "pdf");
  assert.equal(result.classification.confidence, "candidate");
});
