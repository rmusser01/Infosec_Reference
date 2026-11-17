import test from "node:test";
import assert from "node:assert/strict";
import { parseDocument } from "../../tools/navigation/parse.mjs";

test("active empty-destination links are reported while fenced author templates remain examples", () => {
  const doc = parseDocument(
    '# Reader page\n- []()\n- [Pending subject]()\n```md\n- []()\n```\n[Current page](#)\n[Pending][p]\n\n[p]: <>\n\n<a href="">Pending</a>\n<a id="alias"></a>\n',
    "x.md",
  );
  assert.deepEqual(
    doc.issues.map(({ code, line, severity }) => ({ code, line, severity })),
    [
      { code: "empty-link-destination", line: 2, severity: "error" },
      { code: "empty-link-destination", line: 3, severity: "error" },
      { code: "empty-link-destination", line: 8, severity: "error" },
      { code: "empty-link-destination", line: 12, severity: "error" },
    ],
  );
});

test("headings ignore fenced examples, strip HTML, and suffix repeated headings", () => {
  const doc = parseDocument(
    '# Title\n## <a name="old"></a>A & B\n## A & B\n```md\n## Fake\n```\n',
    "x.md",
  );
  assert.deepEqual(
    doc.headings.map((h) => [h.text, h.fragment, h.line]),
    [
      ["Title", "title", 1],
      ["A & B", "a--b", 2],
      ["A & B", "a--b-1", 3],
    ],
  );
  assert(doc.anchors.some((a) => a.fragment === "old"));
  assert(!doc.anchors.some((a) => a.fragment === "fake"));
});
test("records named anchors, malformed opening anchors and exact duplicate IDs", () => {
  const doc = parseDocument(
    '<a name="Legacy">\n<a id="Legacy"></a>\n<a name="Other"\n',
    "x.md",
  );
  assert.equal(doc.anchors.filter((a) => a.fragment === "Legacy").length, 2);
  assert(doc.issues.some((i) => i.code === "malformed-anchor"));
});
test("extracts nested Markdown destinations, reference links, images and bare GFM URLs with positions", () => {
  const doc = parseDocument(
    "[paper](https://example.org/a_(b).pdf)\n[ref][id]\n\n[id]: https://example.org/report\n\n![inline](https://example.org/fig.png)\nhttps://example.org/bare\n",
    "x.md",
  );
  assert.deepEqual(
    doc.links.map((l) => [l.url, l.kind, l.line]),
    [
      ["https://example.org/a_(b).pdf", "link", 1],
      ["https://example.org/report", "link", 2],
      ["https://example.org/fig.png", "image", 6],
      ["https://example.org/bare", "link", 7],
    ],
  );
});
test("extracts HTML href/src while ignoring anchor examples in code", () => {
  const doc = parseDocument(
    '<a href="https://example.org/?a=1&amp;b=2">Link</a>\n<img src="pic.png">\n`<a name="fake">`',
    "x.md",
  );
  assert.equal(doc.links[0].url, "https://example.org/?a=1&b=2");
  assert.equal(doc.links[1].kind, "image");
  assert(!doc.anchors.some((a) => a.fragment === "fake"));
});
test("reference definitions use the first definition, matching rendered Markdown", () => {
  const doc = parseDocument(
    "[x][id]\n\n[id]: first.md\n[id]: second.md\n",
    "x.md",
  );
  assert.equal(doc.links[0].url, "first.md");
});
