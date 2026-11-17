import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";

function outline(path) {
  const doc = parseDocument(readFileSync(path, "utf8"), path);
  function parents(line) {
    const stack = [];
    for (const heading of doc.headings.filter((h) => h.line <= line)) {
      while (stack.at(-1)?.depth >= heading.depth) stack.pop();
      stack.push(heading);
    }
    return stack.map((h) => h.text);
  }
  return { doc, parents };
}

test("DFIR subjects expose their resource groups within the original major subjects", () => {
  const { doc, parents } = outline("Draft/DFIR.md");
  for (const [label, expected] of [
    [
      "incidentresponse.com playbooks",
      ["Incident Response", "Methodologies/Playbooks"],
    ],
    ["TheHive", ["Incident Response", "Platforms"]],
    ["Dispatch - Netflix", ["Incident Response", "Response Automation"]],
    [
      "Digging Up the Past: Windows Registry Forensics Revisited - David Via",
      ["Windows Forensics", "Articles/Blogposts/Writeups", "Registry"],
    ],
    [
      "SQLite-Parser",
      [
        "General Forensics(Systems Agnostic - as much as one can be)",
        "Tools",
        "SQLite",
      ],
    ],
  ]) {
    const resource = doc.links.find((link) => link.label === label);
    assert(resource, `Missing ${label}`);
    assert.deepEqual(parents(resource.line).slice(1), expected);
  }
  for (const subject of [
    "Cloud Forensics",
    "Image Forensics",
    "Bootkit Disk Forensics",
  ])
    assert.equal(doc.headings.find((h) => h.text === subject)?.depth, 2);
});

test("cloud providers and ELK components have the intended subject parents", () => {
  const { doc, parents } = outline("Draft/L-SM-TH.md");
  for (const provider of ["AWS"]) {
    const h = doc.headings.find((h) => h.text === provider);
    assert(h, `Missing provider ${provider}`);
    assert.deepEqual(parents(h.line).slice(-2), ["Cloud-based", provider]);
  }
  for (const component of ["101", "ElasticSearch", "LogStash", "Kibana"]) {
    const h = doc.headings.find(
      (h) =>
        h.line > doc.anchors.find((a) => a.fragment === "elk").line &&
        h.text === component,
    );
    assert(h, `Missing ELK component ${component}`);
    assert.deepEqual(parents(h.line).slice(-2), ["ELK Stack", component]);
  }
});

test("exploit writeup categories do not absorb unrelated resources", () => {
  const { doc, parents } = outline("Draft/Exploit_Dev.md");
  const mips = doc.links.find(
    (l) => l.url === "https://www.exploit-db.com/docs/39658.pdf",
  );
  assert.deepEqual(parents(mips.line).slice(-2), ["Exploit writeups", "MIPS"]);
  const flash = doc.links.find((l) =>
    l.label.startsWith("Smashing the Heap with Vector:"),
  );
  assert.deepEqual(parents(flash.line).slice(-2), [
    "Exploit writeups",
    "Unsorted writeups",
  ]);
  for (const category of [
    "Temporal Return Address",
    "iOS",
    "ROP writeups",
    "UAF writeups",
    "Extended: *alloc/Heap",
  ]) {
    const h = doc.headings.find((h) => h.text === category);
    assert(h, `Missing ${category}`);
    assert.deepEqual(parents(h.line).slice(-2), ["Exploit writeups", category]);
  }
});

test("network duplicate subjects share one heading destination", () => {
  const { doc } = outline("Draft/Network_Attacks.md");
  for (const subject of ["Pivoting", "Vendor Specific Stuff"])
    assert.equal(doc.headings.filter((h) => h.text === subject).length, 1);
  for (const fragment of [
    "ref-network-41",
    "ref-network-42",
    "ref-network-52",
    "ref-network-53",
    "pivot",
    "vendor",
  ])
    assert(
      doc.anchors.some((a) => a.fragment === fragment),
      `Missing ${fragment}`,
    );
});
