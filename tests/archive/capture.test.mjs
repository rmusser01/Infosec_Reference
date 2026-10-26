import test from "node:test";
import assert from "node:assert/strict";
import {
  verifyCapture,
  captureUrl,
  processingQueues,
} from "../../tools/archive/capture.mjs";

const snapshot = {
  state: "article",
  url: "https://example.org/final",
  text: "Article text ".repeat(20),
  images: ["https://example.org/figure.png"],
  embeds: [],
  links: [],
};
const records = [
  {
    id: "<1>",
    url: snapshot.url,
    status: 200,
    contentType: "text/html",
    type: "response",
  },
  {
    id: "<2>",
    url: snapshot.images[0],
    status: 200,
    contentType: "image/png",
    type: "response",
  },
  {
    id: "<3>",
    url: "urn:text:" + snapshot.url,
    text: snapshot.text,
    type: "resource",
  },
];
test("capture verification requires article text, every figure, integrity and actual offline replay independently", () => {
  const qa = {
    comparison: {
      textMatch: 1,
      resourceCounts: { crawlGood: 2, replayGood: 2, replayBad: 0 },
    },
    urls: {
      [snapshot.url]: { status: 200 },
      [snapshot.images[0]]: { status: 200 },
    },
  };
  assert.equal(
    verifyCapture(snapshot, { integrityState: "verified", records }, qa)
      .captureState,
    "complete",
  );
  assert.equal(
    verifyCapture(snapshot, { integrityState: "verified", records }, null)
      .replayState,
    "not-tested",
  );
  assert.equal(
    verifyCapture(
      snapshot,
      {
        integrityState: "verified",
        records: records.filter((r) => r.id !== "<2>"),
      },
      qa,
    ).captureState,
    "partial",
  );
  assert.equal(
    verifyCapture(
      { ...snapshot, imageFailures: [snapshot.images[0]] },
      { integrityState: "verified", records },
      qa,
    ).captureState,
    "partial",
  );
  assert.equal(
    verifyCapture(
      { ...snapshot, state: "access-wall" },
      { integrityState: "verified", records },
      qa,
    ).captureState,
    "inaccessible",
  );
  assert.equal(
    verifyCapture(snapshot, { integrityState: "failed", records }, qa)
      .captureState,
    "partial",
  );
  assert.equal(
    verifyCapture(
      snapshot,
      { integrityState: "verified", records },
      { ...qa, urls: { [snapshot.url]: { status: 200 } } },
    ).replayState,
    "partial",
  );
});
test("non-text jobs remain queued without starting a browser", async () => {
  const result = await captureUrl(
    {
      resourceId: "pdf",
      originalUrl: "https://example.org/paper.pdf",
      queue: "pdf",
      sourceReferences: [],
    },
    {},
    {},
  );
  assert.equal(result.captureState, "deferred");
  assert.equal(result.processingQueue, "pdf");
  assert.deepEqual(result.objects, []);
});

test("redirected pages use the requested URL for Browsertrix text metadata and the final URL for HTML", () => {
  const redirected = { ...snapshot, requestedUrl: "https://example.org/start" };
  const redirectedRecords = records.map((r) =>
    r.type === "resource"
      ? { ...r, url: "urn:text:https://example.org/start" }
      : r,
  );
  const result = verifyCapture(
    redirected,
    { integrityState: "verified", records: redirectedRecords },
    null,
  );
  assert.equal(result.captureState, "complete");
});

test("discovered PDFs and embedded media retain parent provenance without queuing article figures", () => {
  const discovered = processingQueues(
    {
      ...snapshot,
      links: ["https://example.org/paper.pdf"],
      embeds: [{ url: "https://example.org/movie.mp4", kind: "video" }],
    },
    {
      resourceId: "parent",
      sourceReferences: [{ path: "Draft/a.md", line: 12 }],
    },
  );
  assert.deepEqual(
    discovered.map((e) => e.queue),
    ["pdf", "video"],
  );
  assert(
    discovered.every(
      (e) =>
        e.parentResourceId === "parent" && e.sourceReferences[0].line === 12,
    ),
  );
  assert(!discovered.some((e) => e.url === snapshot.images[0]));
});
