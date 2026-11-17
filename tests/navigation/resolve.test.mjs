import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { resolveInternalLink } from "../../tools/navigation/resolve.mjs";

test("resolves encoded paths, same-repository GitHub URLs and exact-case fragments", () => {
  const root = mkdtempSync(join(process.cwd(), ".nav-test-"));
  try {
    mkdirSync(join(root, "Draft"));
    writeFileSync(
      join(root, "Draft/A & B.md"),
      '# Test\n<a name="OldCase"></a>\n',
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "Draft/A%20%26%20B.md#OldCase")
        .kind,
      "internal",
    );
    assert.equal(
      resolveInternalLink(
        root,
        "README.md",
        "https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/A%20%26%20B.md#test",
      ).kind,
      "internal",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "Draft/A%20%26%20B.md#oldcase")
        .code,
      "missing-fragment",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "Draft/a%20%26%20B.md").code,
      "missing-file",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "draft/A%20%26%20B.md").code,
      "missing-file",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "draft").code,
      "missing-file",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "https://example.org/x").kind,
      "external",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "../outside.md").code,
      "outside-root",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "Draft").kind,
      "directory",
    );
    assert.equal(
      resolveInternalLink(root, "README.md", "Draft/%broken").code,
      "invalid-url",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
