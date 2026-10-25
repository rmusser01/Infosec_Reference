import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";
import { resolveInternalLink } from "../../tools/navigation/resolve.mjs";

const snapshot = JSON.parse(
  readFileSync(new URL("./fixtures/migration-resources.json", import.meta.url)),
);
for (const [path, original] of Object.entries(snapshot))
  test(`${path} has managed navigation without losing resources or legacy anchors`, () => {
    const source = readFileSync(path, "utf8"),
      doc = parseDocument(source, path);
    const manifest = JSON.parse(readFileSync("navigation/topics.json", "utf8"));
    const baseline = JSON.parse(
      readFileSync("navigation/legacy-errors.json", "utf8"),
    );
    assert(manifest.tocPages.includes(path));
    assert(source.includes("<!-- nav:toc:start -->"));
    assert(!baseline.some((entry) => entry.path === path));
    let preservedSource = source;
    for (const { from, to } of original.urlCorrections ?? []) {
      assert(
        doc.links.some((link) => link.url === to),
        `Missing corrected destination ${to}`,
      );
      preservedSource = preservedSource.replace(to, from);
    }
    assert.equal(
      createHash("sha256")
        .update(
          [...preservedSource.matchAll(/https?:\/\/[^\s<>"']+/g)]
            .map((m) => m[0])
            .sort()
            .join("\n"),
        )
        .digest("hex"),
      original.rawExternalSha256,
    );
    const resources = doc.links
      .filter((link) => link.kind === "link" && /^https?:/.test(link.url))
      .map((link) => link.url);
    for (const url of original.parsedExternal) {
      const index = resources.indexOf(url);
      assert(index >= 0, `Lost rendered resource ${url}`);
      resources.splice(index, 1);
    }
    for (const fragment of original.anchors)
      assert(
        doc.anchors.some((a) => a.fragment === fragment),
        `Lost legacy anchor ${fragment}`,
      );
    const seen = new Set();
    for (const anchor of doc.anchors) {
      assert(!seen.has(anchor.fragment), `Duplicate anchor ${anchor.fragment}`);
      seen.add(anchor.fragment);
    }
    const documents = new Map([[path, doc]]);
    for (const link of doc.links) {
      const result = resolveInternalLink(
        process.cwd(),
        path,
        link.url,
        documents,
      );
      assert.notEqual(
        result.kind,
        "error",
        `${path}:${link.line} ${link.url}: ${result.code}`,
      );
    }
  });
