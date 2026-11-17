import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";
import { resolveInternalLink } from "../../tools/navigation/resolve.mjs";
const snapshot = JSON.parse(
  readFileSync(new URL("./fixtures/pilot-resources.json", import.meta.url)),
);
for (const [path, original] of Object.entries(snapshot))
  test(`pilot ${path} retains resources/aliases and has valid internal navigation`, () => {
    const source = readFileSync(path, "utf8"),
      doc = parseDocument(source, path),
      docs = new Map([[path, doc]]);
    assert(source.includes("<!-- nav:toc:start -->"));
    assert.deepEqual(
      [...source.matchAll(/https?:\/\/[^\s<>"']+/g)].map((m) => m[0]).sort(),
      original.rawExternal,
    );
    const current = doc.links
      .filter((l) => /^https?:/.test(l.url))
      .map((l) => l.url);
    for (const url of original.external)
      assert(current.includes(url), `Lost parsed resource ${url}`);
    for (const fragment of original.anchors)
      assert(
        doc.anchors.some((a) => a.fragment === fragment),
        `Lost legacy anchor ${fragment}`,
      );
    const seen = new Set();
    for (const a of doc.anchors) {
      assert(!seen.has(a.fragment), `Duplicate anchor ${a.fragment}`);
      seen.add(a.fragment);
    }
    for (const link of doc.links) {
      const r = resolveInternalLink(process.cwd(), path, link.url, docs);
      assert.notEqual(
        r.kind,
        "error",
        `${path}:${link.line} ${link.url} ${r.code}`,
      );
    }
  });
