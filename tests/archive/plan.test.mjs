import test from "node:test";
import assert from "node:assert/strict";
import { buildArchivePlan } from "../../tools/archive/plan.mjs";
const row = (url, type = "unknown") => ({
  id: url,
  url,
  type_candidate: type,
  source_references: [{ path: "Draft/a.md", line: 1, original_url: url }],
});
test("separates candidate PDFs/videos/non-text from type confirmation and confirmed HTML", () => {
  const plan = buildArchivePlan(
    [
      row("https://e.org/a.pdf", "pdf"),
      row("https://youtu.be/id", "video"),
      row("https://e.org/a.zip", "archive"),
      row("https://e.org/unknown"),
      row("https://e.org/article"),
    ],
    {
      evidence: [
        {
          originalUrl: "https://e.org/article",
          finalUrl: "https://e.org/article",
          availabilityState: "reachable",
          contentType: "text/html",
        },
      ],
    },
  );
  assert.deepEqual(
    plan.jobs.map((j) => j.queue),
    ["pdf", "video", "other_nontext", "type_confirmation", "web_capture"],
  );
  assert(plan.jobs.every((j) => j.status === "pending"));
  assert.equal(plan.jobs[4].capturePolicy.images, "article-only");
});
test("only skips existing captures with explicit verified durability, integrity and replay", () => {
  const records = [row("https://e.org/a"), row("https://e.org/b")];
  const evidence = records.map((r) => ({
    originalUrl: r.url,
    availabilityState: "reachable",
    contentType: "text/html",
  }));
  const verified = {
    originalUrl: records[0].url,
    captureState: "complete",
    storageState: "verified",
    integrityState: "verified",
    replayState: "verified",
    objects: [
      { uri: "s3://archive/a.warc.gz", sha256: "a".repeat(64), bytes: 100 },
    ],
  };
  const plan = buildArchivePlan(records, {
    evidence,
    priorCaptures: [
      verified,
      { ...verified, originalUrl: records[1].url, storageState: "temporary" },
    ],
  });
  assert.equal(plan.jobs[0].status, "already-preserved");
  assert.equal(plan.jobs[1].status, "pending");
  assert.equal(plan.summary.alreadyPreserved, 1);
});
test("blocked or missing URLs remain accounted for, and no bytes/capture success are invented", () => {
  const plan = buildArchivePlan([row("https://e.org/a")], {
    evidence: [
      {
        originalUrl: "https://e.org/a",
        availabilityState: "missing",
        httpStatus: 404,
      },
    ],
  });
  assert.equal(plan.jobs[0].status, "needs-review");
  assert.equal(plan.summary.total, 1);
  assert.equal(plan.jobs[0].warcRecordIds, undefined);
});
test("uncertain/error/timeout evidence is reviewed without misrouting non-text resources", () => {
  for (const observation of [
    { httpStatus: 403, contentType: "text/html" },
    { httpStatus: 429, contentType: "text/html" },
    { httpStatus: 500, contentType: "text/html" },
    { error: "Timeout" },
  ]) {
    const plan = buildArchivePlan([row("https://e.org/report.pdf", "pdf")], {
      evidence: [
        {
          originalUrl: "https://e.org/report.pdf",
          availabilityState: "uncertain",
          ...observation,
        },
      ],
    });
    assert.equal(plan.jobs[0].queue, "pdf");
    assert.equal(plan.jobs[0].status, "needs-review");
  }
});
