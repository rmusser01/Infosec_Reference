import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDocument } from "../../tools/navigation/parse.mjs";
import { resolveInternalLink } from "../../tools/navigation/resolve.mjs";

test("ATT&CK landing routes every existing category to its matching local mapping", () => {
  const path = "Draft/ATT&CK-Stuff/README.md";
  const source = readFileSync(path, "utf8");
  const doc = parseDocument(source, path);
  assert.match(source, /^# ATT&CK mappings\n/);
  const pre = {
    "Adversary Opsec": "Adversary_OPSEC",
    "Build Capabilities": "Build_Capabilities",
    "Organization Informational Gathering": "Organizationa_ Information_Gathering",
    "Organizational Weakness": "Organizational_Weakness",
    "People Information Gathering": "People_Information_Gathering",
    "People Weakness Identification": "People_Weakness_Identification",
    "Persona Development": "Persona_Development",
    "Priority Definition Planning": "Priority_Definition _lanning",
    "Priority Definition Directive": "Priority_Definition_Directive",
    "Stage Capabilities": "Stage_Capabilities",
    "Target Selection": "Target_Selection",
    "Technical Information Gathering": "Technical_Information_Gathering",
    "Test Capabilities": "Test_Capabilities",
  };
  const attack = {
    Collection: "Collection",
    "Command and Control": "Command_and_Control",
    "Credential Access": "Credential_Access",
    "Defense Evasion": "Defense_Evasion",
    Discovery: "Discovery",
    Execution: "Execution",
    Exfiltration: "Exfiltration",
    "Initial Access": "Initial_Access",
    "Lateral Movement": "Lateral Movement",
    Persistence: "Persistence",
    "Privilege Escalation": "Privilege_Escalation",
  };
  for (const [folder, entries] of [["Pre-ATT&CK", pre], ["ATT&CK", attack]])
    for (const [label, filename] of Object.entries(entries)) {
      const link = doc.links.find((link) => link.label === label);
      assert(link, `Missing ${label}`);
      const result = resolveInternalLink(process.cwd(), path, link.url, new Map());
      assert.equal(result.kind, "internal", `${label}: ${link.url}`);
      assert.equal(result.path, `Draft/ATT&CK-Stuff/${folder}/${filename}.md`);
    }
  for (const [url, count] of [
    ["https://attack.mitre.org/pre-attack/index.php/Main_Page", 1],
    ["https://attack.mitre.org/wiki/Main_Page", 1],
    ["https://github.com/redcanaryco/atomic-red-team", 2],
    ["https://github.com/mitre/caldera", 1],
    ["https://github.com/uber-common/metta", 1],
  ])
    assert.equal(doc.links.filter((link) => link.url === url).length, count);
  assert(!JSON.parse(readFileSync("navigation/legacy-errors.json")).some((entry) => entry.path === path));
});
