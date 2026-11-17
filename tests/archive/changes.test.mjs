import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  writeFile,
  mkdir,
  rm,
  readFile,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { addedResources } from "../../tools/archive/changes.mjs";
const cli = new URL("../../tools/archive/changes.mjs", import.meta.url)
  .pathname;

test("resume plans include due rate-limited receipts and do not let future jobs consume the batch", async () => {
  const root = await mkdtemp(join(tmpdir(), "archive-resume-"));
  try {
    const git = (...args) => execFileSync("git", args, { cwd: root });
    git("init", "-q");
    git("config", "user.email", "test@example.invalid");
    git("config", "user.name", "Test");
    await writeFile(join(root, "README.md"), "No new URLs");
    git("add", ".");
    git("commit", "-qm", "base");
    await mkdir(join(root, "navigation"));
    await writeFile(
      join(root, "navigation/wayback-captures.jsonl"),
      [
        {
          originalUrl: "https://example.org/future",
          state: "pending",
          retryAt: new Date(Date.now() + 120000).toISOString(),
        },
        {
          originalUrl: "https://example.org/due",
          state: "deferred",
          httpStatus: 429,
          retryAt: "2020-01-01T00:00:00Z",
        },
      ]
        .map(JSON.stringify)
        .join("\n") + "\n",
    );
    execFileSync(
      process.execPath,
      [cli, "--resume", "--output", "archive-data/plan"],
      { cwd: root },
    );
    const plan = JSON.parse(
      await readFile(join(root, "archive-data/plan/changes.json"), "utf8"),
    );
    assert.deepEqual(
      plan.jobs.map((j) => j.originalUrl),
      ["https://example.org/due"],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("change CLI rejects symlinked catalog and metadata paths without touching unrelated files", async () => {
  const root = await mkdtemp(join(tmpdir(), "archive-paths-"));
  const outside = await mkdtemp(join(tmpdir(), "archive-outside-"));
  try {
    const git = (...args) => execFileSync("git", args, { cwd: root });
    git("init", "-q");
    git("config", "user.email", "test@example.invalid");
    git("config", "user.name", "Test");
    await writeFile(join(root, "README.md"), "No URLs");
    git("add", ".");
    git("commit", "-qm", "base");
    await mkdir(join(root, "navigation"));
    await mkdir(join(root, "docs"));
    await writeFile(join(root, "navigation/archive-policy.json"), "{}");
    await writeFile(join(outside, "README.md"), "untouched");
    await symlink(outside, join(root, "docs/archives"));
    const run = () =>
      execFileSync(process.execPath, [cli, "--execute", "--wayback-only"], {
        cwd: root,
        stdio: "pipe",
      });
    assert.throws(run, /Unsafe repository path/);
    assert.equal(
      await readFile(join(outside, "README.md"), "utf8"),
      "untouched",
    );
    await rm(join(root, "docs/archives"));
    await mkdir(join(root, "docs/archives"));
    await writeFile(join(outside, "ledger"), "[]");
    await symlink(
      join(outside, "ledger"),
      join(root, "navigation/wayback-captures.jsonl"),
    );
    assert.throws(run, /Unsafe repository path/);
    assert.equal(await readFile(join(outside, "ledger"), "utf8"), "[]");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("Git comparison finds only new resource URLs, including uncommitted files, with source provenance", async () => {
  const root = await mkdtemp(join(tmpdir(), "archive-changes-"));
  const git = (...args) =>
    execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
  try {
    git("init", "-q");
    git("config", "user.email", "test@example.invalid");
    git("config", "user.name", "Test");
    await mkdir(join(root, "Draft"));
    await mkdir(join(root, "docs"));
    await writeFile(
      join(root, "Draft/a.md"),
      "[Old](https://example.org/old#one)\n",
    );
    git("add", ".");
    git("commit", "-qm", "base");
    await writeFile(
      join(root, "Draft/a.md"),
      "[Moved](https://example.org/old#two)\n[New](https://example.org/new?x=1#section)\n[Same](https://example.org/new?x=1)\n![Ignore](https://example.org/image.png)\n```\nhttps://example.org/code\n```\n",
    );
    await writeFile(
      join(root, "Draft/new.md"),
      "[PDF](https://example.org/paper.pdf)",
    );
    await writeFile(
      join(root, "docs/new.md"),
      "[Not a resource](https://example.org/devdocs)",
    );
    const rows = await addedResources(root, "HEAD");
    assert.deepEqual(
      rows.map((r) => r.url),
      ["https://example.org/new?x=1", "https://example.org/paper.pdf"],
    );
    assert.equal(rows[0].source_references.length, 2);
    assert.equal(
      rows[0].source_references[0].original_url,
      "https://example.org/new?x=1#section",
    );
    git("add", ".");
    git("commit", "-qm", "new");
    assert.deepEqual(await addedResources(root, "HEAD~1", "HEAD"), rows);
    assert.deepEqual(await addedResources(root, "HEAD", "HEAD"), []);
    await assert.rejects(addedResources(root, "--help"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
