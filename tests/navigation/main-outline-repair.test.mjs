import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";
import { resolveInternalLink } from "../../tools/navigation/resolve.mjs";

function outline(path) {
  const source = readFileSync(path, "utf8");
  const doc = parseDocument(source, path);
  const heading = (id) => {
    const anchor = doc.anchors.find((a) => a.fragment === id);
    assert(anchor, `Missing destination ${id}`);
    const result = doc.headings.find((h) => h.line === anchor.line);
    assert(result, `${id} must identify a navigable subject`);
    return result;
  };
  const parent = (id) => {
    const child = heading(id);
    return doc.headings.findLast(
      (h) => h.line < child.line && h.depth < child.depth,
    );
  };
  return { source, doc, heading, parent };
}

test("LDAP subsubjects stay within LDAP", () => {
  const { heading, parent } = outline("Draft/Active_Directory.md");
  for (const id of [18, 19, 20, 21, 141, 142])
    assert.equal(parent(`ref-ad-${id}`), heading("ref-ad-17"));
});

test("Kerberos techniques, delegation types, and ticket types have distinct parents", () => {
  const { heading, parent } = outline("Draft/Active_Directory.md");
  for (const id of [57, 58, 59, 63, 64, 65, 66, 67, 68, 136, 143])
    assert.equal(parent(`ref-ad-${id}`), heading("ref-ad-56"));
  for (const id of [60, 61, 62])
    assert.equal(parent(`ref-ad-${id}`), heading("ref-ad-59"));
  for (const id of [69, 70, 71, 72])
    assert.equal(parent(`ref-ad-${id}`), heading("ref-ad-136"));
});

test("independent AD attacks and the Wii U article group have their intended peers", () => {
  const ad = outline("Draft/Active_Directory.md");
  for (const id of [137, 138])
    assert.equal(ad.parent(`ref-ad-${id}`), ad.heading("ref-ad-81"));
  const adape = ad.doc.links.find((l) => l.label === "ADAPE-Script");
  assert.equal(
    ad.doc.headings.findLast((h) => h.line < adape.line),
    ad.heading("ref-ad-81"),
  );
  assert.equal(ad.parent("ref-ad-139"), ad.parent("ref-ad-87"));
  assert.equal(ad.parent("ref-ad-140"), ad.parent("ref-ad-88"));
  const games = outline("Draft/Games.md");
  assert.equal(games.parent("ref-games-15"), games.heading("ref-games-14"));
});

test("pending Web resources render as links under a separate pending section", () => {
  const { source, doc, heading, parent } = outline("Draft/Web.md");
  const pending = heading("ref-web-233");
  for (const id of [234, 238, 239, 240, 241])
    assert.equal(parent(`ref-web-${id}`), pending);
  const tail = source
    .split("\n")
    .slice(pending.line - 1)
    .join("\n");
  assert(!tail.includes("```"));
  const rawURLs = [...tail.matchAll(/https?:\/\/[^\s<>"']+/g)];
  assert(rawURLs.length > 0);
  assert.equal(
    doc.links.filter((l) => l.line > pending.line).length,
    rawURLs.length,
  );
  assert(doc.anchors.some((a) => a.fragment === "jsframeworks"));
  assert(doc.anchors.some((a) => a.fragment === "js-frameworks"));
});

test("hardware pointers resolve and the wireless-keyboard resource is outside Cable Modem", () => {
  for (const [path, targets] of [
    [
      "Draft/Embedded.md",
      ["bios_uefi.md", "RE.md", "Network_Attacks.md#printers"],
    ],
    ["Draft/RE.md", ["Embedded.md"]],
  ]) {
    const { doc } = outline(path);
    for (const url of targets) {
      assert(doc.links.some((l) => l.url === url));
      assert.notEqual(
        resolveInternalLink(process.cwd(), path, url).kind,
        "error",
      );
    }
  }
  const { doc, heading } = outline("Draft/Embedded.md");
  const keykeriki = doc.links.find((l) => l.label === "Keykeriki v2.0");
  assert(keykeriki);
  assert.equal(
    doc.headings.findLast((h) => h.line < keykeriki.line),
    heading("ref-embedded-125"),
  );
});
