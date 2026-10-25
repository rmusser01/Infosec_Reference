import test from "node:test";
import assert from "node:assert/strict";
import {
  classifyResource,
  collectResources,
} from "../../tools/navigation/resources.mjs";
test("MIME evidence routes extensionless documents and overrides misleading suffixes", () => {
  assert.equal(
    classifyResource(
      { url: "https://e.org/download?id=1" },
      { contentType: "application/pdf" },
    ).type,
    "pdf",
  );
  assert.equal(
    classifyResource(
      { url: "https://e.org/a.pdf" },
      { contentType: "text/html" },
    ).type,
    "webpage",
  );
  assert.equal(
    classifyResource({ url: "https://e.org/a.pdf" }).confidence,
    "candidate",
  );
  assert.equal(
    classifyResource(
      { url: "https://e.org/a.pdf" },
      { finalUrl: "https://e.org/a.mp4" },
    ).type,
    "video",
  );
  assert.equal(
    classifyResource({ url: "https://youtu.be/id" }).processingQueue,
    "video",
  );
  assert.equal(
    classifyResource({ url: "https://e.org/a.zip" }).processingQueue,
    "other_nontext",
  );
  assert.equal(
    classifyResource({ url: "https://e.org/unknown" }).confidence,
    "unknown",
  );
});
test("deduplicates fragments, preserves queries and references, excludes inline images and fenced examples", () => {
  const docs = [
    {
      path: "Draft/x.md",
      source:
        "[A](https://e.org/a.pdf#page=2)\n[B](https://e.org/a.pdf#page=9)\n[C](https://e.org/a.pdf?v=2)\n![article](https://e.org/fig.png)\n```\nhttps://e.org/fake.pdf\n```\n",
    },
  ];
  const rows = collectResources(docs);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].source_references.length, 2);
  assert.equal(rows[0].url, "https://e.org/a.pdf");
  assert.equal(rows[0].processing_status, "pending");
  assert.equal(
    rows[0].source_references[0].original_url,
    "https://e.org/a.pdf#page=2",
  );
});
test("malformed URL escapes remain reviewable instead of aborting the whole inventory", () => {
  assert.doesNotThrow(() => classifyResource({ url: "https://e.org/bad%zz" }));
  assert.equal(
    classifyResource({ url: "https://e.org/bad%zz" }).confidence,
    "unknown",
  );
});
test("resource progress survives regeneration through the separate progress ledger", () => {
  const docs = [{ path: "Draft/x.md", source: "[PDF](https://e.org/a.pdf)" }];
  const initial = collectResources(docs),
    id = initial[0].id;
  assert.equal(
    collectResources(docs, { [id]: { processing_status: "extracted" } })[0]
      .processing_status,
    "extracted",
  );
  assert.throws(
    () => collectResources(docs, { [id]: { processing_status: "nonsense" } }),
    /processing status/i,
  );
});
test("error-page MIME never displaces provisional type of the requested resource", () => {
  for (const httpStatus of [403, 429, 500]) {
    const r = classifyResource(
      { url: "https://e.org/report.pdf" },
      {
        finalUrl: "https://e.org/error",
        httpStatus,
        availabilityState: "uncertain",
        contentType: "text/html",
      },
    );
    assert.equal(r.type, "pdf");
    assert.equal(r.confidence, "candidate");
  }
});
