import test from "node:test";
import assert from "node:assert/strict";
import { saveWayback } from "../../tools/archive/wayback.mjs";
import { waybackCatalog } from "../../tools/archive/changes.mjs";
const url = "https://example.org/article?q=1";
const lookupHost = async () => [{ address: "93.184.215.14" }];
const response = (body, status = 200, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers,
  });

test("catalog warns when a confirmed snapshot contains unrelated replacement content", () => {
  const saved = {
    originalUrl: "https://example.org/tool",
    archivedUrl: "https://replacement.example/wallpapers",
    timestamp: "20261026120000",
    state: "saved",
  };
  assert(!waybackCatalog([saved]).includes("original resource not recovered"));
  const catalog = waybackCatalog([
    saved,
    { ...saved, snapshotContentState: "replacement" },
  ]);
  assert(catalog.includes("original resource not recovered"));
  assert(catalog.includes("https://replacement.example/wallpapers"));
  assert.equal(catalog.split("Wayback snapshot").length - 1, 1);
});

test("Wayback canonical snapshot identities require an observed final URL and catalog links use that identity", async () => {
  const originalUrl = "http://example.blogspot.fr/post";
  const finalUrl = "https://example.blogspot.com/post";
  const options = {
    prior: { state: "pending", jobId: "spn2-canonical" },
    lookupHost,
    fetchImpl: async () =>
      response({
        status: "success",
        timestamp: "20261025120000",
        original_url: finalUrl,
      }),
  };
  const result = await saveWayback(originalUrl, { ...options, finalUrl });
  assert.equal(result.state, "saved");
  assert.equal(result.archivedUrl, finalUrl);
  assert.equal(
    result.archiveUrl,
    "https://web.archive.org/web/20261025120000/" + finalUrl,
  );
  assert(waybackCatalog([result]).includes("](<" + result.archiveUrl + ">)"));
  for (const candidate of [undefined, "https://unrelated.example/post"]) {
    const rejected = await saveWayback(originalUrl, {
      ...options,
      finalUrl: candidate,
    });
    assert.equal(rejected.state, "pending");
    assert.equal(rejected.reason, "Unconfirmed snapshot identity");
  }
});
test("Wayback requires job success, resumes saved jobs, and never mistakes a login/error page for a snapshot", async () => {
  const requests = [],
    records = [];
  const replies = [
    response('<script>var job="spn2-abc-123";</script>'),
    response({ status: "pending" }),
    response({
      status: "success",
      timestamp: "20261025120000",
      original_url: url,
    }),
  ];
  const fetchImpl = async (target, options) => {
    requests.push({ target, options });
    return replies.shift();
  };
  const options = {
    lookupHost,
    fetchImpl,
    record: async (r) => records.push(r),
    sleep: async () => {},
  };
  const result = await saveWayback(url, options);
  assert.equal(result.state, "saved");
  assert.equal(
    result.archiveUrl,
    "https://web.archive.org/web/20261025120000/" + url,
  );
  assert.equal(
    records[0].state,
    "uncertain",
    "persist in-flight submission before sending",
  );
  assert.equal(records[1].state, "pending", "persist job ID before polling");
  assert.equal(requests[0].options.method, "POST");
  assert.equal(
    new URLSearchParams(requests[0].options.body).get("capture_outlinks"),
    "0",
  );
  requests.length = 0;
  assert.equal(
    (await saveWayback(url, { ...options, prior: result })).state,
    "saved",
  );
  assert.equal(requests.length, 0, "confirmed snapshots are not resubmitted");
  const resumed = await saveWayback(url, {
    ...options,
    prior: records[1],
    fetchImpl: async (target, options) => {
      assert.notEqual(options.method, "POST");
      return response({
        status: "success",
        timestamp: "20261025120000",
        original_url: url,
      });
    },
  });
  assert.equal(resumed.state, "saved");
  for (const body of [
    "<html>Log in</html>",
    { job_id: "https://evil.invalid" },
    { status: "success", timestamp: "bad" },
  ]) {
    assert.notEqual(
      (
        await saveWayback(url, {
          ...options,
          fetchImpl: async () => response(body),
        })
      ).state,
      "saved",
    );
  }
});
test("Wayback public URL guards and uncertain submissions do not silently retry or claim success", async () => {
  const options = {
    lookupHost,
    sleep: async () => {},
    fetchImpl: async () => {
      throw Error("transport lost");
    },
  };
  const unknown = await saveWayback(url, options);
  assert.equal(unknown.state, "uncertain");
  assert.equal(
    (
      await saveWayback(url, {
        ...options,
        prior: unknown,
        fetchImpl: () => assert.fail("no duplicate submit"),
      })
    ).state,
    "uncertain",
  );
  for (const target of [
    "http://user:pass@example.org/",
    "file:///tmp/a",
    "http://localhost/",
  ]) {
    const result = await saveWayback(target, {
      ...options,
      lookupHost: async () => [{ address: "127.0.0.1" }],
      fetchImpl: () => assert.fail("unsafe URL submitted"),
    });
    assert.equal(result.state, "rejected");
  }
  const throttled = await saveWayback(url, {
    ...options,
    fetchImpl: async () => response("slow", 429, { "Retry-After": "120" }),
  });
  assert.equal(throttled.state, "deferred");
  assert(throttled.retryAt);
  const dnsFailure = await saveWayback(url, {
    ...options,
    lookupHost: async () => {
      throw Error("getaddrinfo ENOTFOUND");
    },
  });
  assert.equal(
    dnsFailure.state,
    "deferred",
    "DNS failures before submission are safe to retry later",
  );
  assert(dnsFailure.retryAt);
});
