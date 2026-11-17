import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";

const document = (filename) => {
  const path = `Draft/ATT&CK-Stuff/ATT&CK/${filename}.md`;
  return parseDocument(readFileSync(path, "utf8"), path);
};

test("consolidated technique outlines retain historical destinations and citation occurrences", () => {
  const privilege = document("Privilege_Escalation");
  for (const [subject, fragment, technique] of [
    ["Plist Modification", "plist-modification", "T1150"],
    ["SID-History Injection", "sid-history-injection", "T1178"],
  ]) {
    assert.equal(
      privilege.headings.filter((h) => h.text === subject).length,
      1,
    );
    for (const alias of [fragment, `${fragment}-1`])
      assert(
        privilege.anchors.some((a) => a.fragment === alias),
        alias,
      );
    assert.equal(
      privilege.links.filter(
        (l) => l.url === `https://attack.mitre.org/wiki/Technique/${technique}`,
      ).length,
      2,
    );
  }
  const scheduled = privilege.headings.find(
    (h) => h.text === "Scheduled Tasks",
  );
  const next = privilege.headings.find(
    (h) => h.depth === 2 && h.line > scheduled.line,
  );
  const repaired = privilege.links.find(
    (l) =>
      l.url ===
      "https://support.microsoft.com/en-us/help/313565/how-to-use-the-at-command-to-schedule-tasks",
  );
  assert(repaired.line > scheduled.line && repaired.line < next.line);
  assert(!repaired.label.includes("Plist"));
  for (let i = 0; i <= 15; i++)
    assert(
      privilege.anchors.some(
        (a) => a.fragment === (i ? `windows-${i}` : "windows"),
      ),
    );

  const discovery = document("Discovery");
  assert(
    discovery.headings
      .filter(
        (h) =>
          !h.text.startsWith("Windows") && /Discovery$|Scanning$/.test(h.text),
      )
      .every((h) => h.depth === 2),
  );
  const remote = discovery.headings.find(
    (h) => h.text === "Remote System Discovery",
  );
  const following = discovery.headings.find(
    (h) => h.depth === 2 && h.line > remote.line,
  );
  assert.equal(
    discovery.headings.filter(
      (h) =>
        h.text === "Windows" && h.line > remote.line && h.line < following.line,
    ).length,
    1,
  );
  for (let i = 0; i <= 17; i++)
    assert(
      discovery.anchors.some(
        (a) => a.fragment === (i ? `windows-${i}` : "windows"),
      ),
    );
  for (const doc of [privilege, discovery]) {
    const fragments = doc.anchors.map((a) => a.fragment);
    assert.equal(new Set(fragments).size, fragments.length, doc.path);
  }
});
