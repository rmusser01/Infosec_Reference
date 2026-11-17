import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { audit } from "../../tools/navigation/audit.mjs";
test("audit distinguishes broken targets, duplicate anchors and unreferenced pages", () => {
  const root = mkdtempSync(join(process.cwd(), ".nav-test-"));
  try {
    mkdirSync(join(root, "Draft"));
    writeFileSync(
      join(root, "README.md"),
      "[a](Draft/a.md#ok)\n[bad](Draft/no.md)\n",
    );
    writeFileSync(
      join(root, "Draft/a.md"),
      '# A\n<a name="ok"></a>\n<a name="twice"></a>\n<a name="twice"></a>\n',
    );
    writeFileSync(join(root, "Draft/orphan.md"), "# Lonely\n");
    const r = audit(root);
    assert(
      r.findings.some(
        (f) =>
          f.code === "missing-file" && f.path === "README.md" && f.line === 2,
      ),
    );
    assert(
      r.findings.some(
        (f) => f.code === "duplicate-anchor" && f.target === "twice",
      ),
    );
    assert(
      r.findings.some(
        (f) => f.code === "orphan-page" && f.path === "Draft/orphan.md",
      ),
    );
    assert.equal(r.summary.pages, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("Markdown symlinks are rejected before external content is read", async () => {
  const { symlinkSync } = await import("node:fs");
  const root = mkdtempSync(join(process.cwd(), ".nav-test-")),
    outside = mkdtempSync(join(process.cwd(), ".nav-test-"));
  try {
    mkdirSync(join(root, "Draft"));
    writeFileSync(join(root, "README.md"), "# Root");
    writeFileSync(
      join(outside, "outside.md"),
      "[outside](https://private.example.invalid/)",
    );
    symlinkSync(join(outside, "outside.md"), join(root, "Draft/unsafe.md"));
    assert.throws(() => audit(root), /symlink|unsafe/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
