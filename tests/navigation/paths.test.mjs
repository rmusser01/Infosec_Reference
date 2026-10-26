import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, symlinkSync, rmSync } from "node:fs";
import { join } from "node:path";
import { repositoryPath } from "../../tools/navigation/paths.mjs";
test("missing outputs are allowed only below safe existing ancestors", () => {
  const root = mkdtempSync(join(process.cwd(), ".nav-test-")),
    outside = mkdtempSync(join(process.cwd(), ".nav-test-"));
  try {
    symlinkSync(outside, join(root, "linked"));
    assert.throws(
      () => repositoryPath(root, "linked/new.md", { allowMissing: true }),
      /symlink|unsafe/i,
    );
    symlinkSync(join(outside, "absent.md"), join(root, "dangling.md"));
    assert.throws(
      () => repositoryPath(root, "dangling.md", { allowMissing: true }),
      /symlink|unsafe/i,
    );
    assert.equal(
      repositoryPath(root, "new.md", { allowMissing: true }),
      join(root, "new.md"),
    );
    assert.throws(
      () => repositoryPath(root, "../outside.md", { allowMissing: true }),
      /unsafe/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
