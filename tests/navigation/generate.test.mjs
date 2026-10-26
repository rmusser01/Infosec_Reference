import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { generate } from "../../tools/navigation/generate.mjs";
import { runInNewContext } from "node:vm";
function fixture() {
  const root = mkdtempSync(join(process.cwd(), ".nav-test-"));
  for (const dir of ["Draft", "navigation"]) mkdirSync(join(root, dir));
  writeFileSync(
    join(root, "README.md"),
    "Intro\r\n<!-- nav:topics:start -->\r\nold\r\n<!-- nav:topics:end -->\r\nFooter\r\n",
  );
  writeFileSync(
    join(root, "Draft/README.md"),
    "# Home\n<!-- nav:topics:start -->\nold\n<!-- nav:topics:end -->\n",
  );
  writeFileSync(
    join(root, "Draft/a.md"),
    "# A\n<!-- nav:toc:start -->\nold\n<!-- nav:toc:end -->\n## Zebra\n## Alpha\n",
  );
  writeFileSync(
    join(root, "navigation/topics.json"),
    JSON.stringify({
      version: 1,
      pages: [
        {
          path: "Draft/a.md",
          title: "A",
          category: "Topics",
          aliases: ["Alias"],
          tocDepth: 3,
          subjects: [{ label: "Zebra", fragment: "zebra", aliases: ["Zed"] }],
        },
      ],
      tocPages: ["Draft/a.md"],
    }),
  );
  return root;
}
test("generated search routes preserve reserved filename characters as path data", () => {
  const root = fixture();
  try {
    writeFileSync(join(root, "Draft/# notes & details.md"), "# Notes\n");
    assert.deepEqual(generate(root).diagnostics, []);
    const window = { $docsify: { search: {} } };
    runInNewContext(readFileSync(join(root, "Draft/search-paths.js"), "utf8"), {
      window,
    });
    const path = window.$docsify.search.paths.find((p) => p.includes("notes"));
    const request = new URL(path + ".md", "http://localhost");
    assert.equal(request.hash, "");
    assert.equal(decodeURIComponent(request.pathname), "/# notes & details.md");
    assert.equal(generate(root, { check: true }).changedPaths.length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("child pages can have generated ToCs without becoming top-level topics", () => {
  const root = fixture();
  try {
    writeFileSync(
      join(root, "Draft/child.md"),
      "# Child\n<!-- nav:toc:start -->\n<!-- nav:toc:end -->\n## Existing subject\nAn existing explanation.\n",
    );
    const path = join(root, "navigation/topics.json"),
      manifest = JSON.parse(readFileSync(path));
    manifest.tocPages.push("Draft/child.md");
    writeFileSync(path, JSON.stringify(manifest));
    assert.deepEqual(generate(root).diagnostics, []);
    assert(
      readFileSync(join(root, "Draft/child.md"), "utf8").includes(
        "[Existing subject](#existing-subject)",
      ),
    );
    assert(
      !readFileSync(join(root, "Draft/_sidebar.md"), "utf8").includes(
        "child.md",
      ),
    );
    assert.equal(generate(root, { check: true }).changedPaths.length, 0);
    manifest.tocPages.push("Draft/missing.md");
    writeFileSync(path, JSON.stringify(manifest));
    assert(
      generate(root).diagnostics.some((d) => d.code === "invalid-toc-page"),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("generates document-order ToCs and sorted subjects; repeated runs are identical and preserve surrounding bytes", () => {
  const root = fixture();
  try {
    const first = generate(root, { check: false });
    assert.equal(first.diagnostics.length, 0);
    const page = readFileSync(join(root, "Draft/a.md"), "utf8");
    assert(page.indexOf("[Zebra](#zebra)") < page.indexOf("[Alpha](#alpha)"));
    assert(
      readFileSync(join(root, "README.md"), "utf8").startsWith("Intro\r\n"),
    );
    assert(
      readFileSync(join(root, "README.md"), "utf8").endsWith("Footer\r\n"),
    );
    assert(
      readFileSync(join(root, "Draft/Subject_Index.md"), "utf8").includes(
        "[Zed](a.md#zebra)",
      ),
    );
    assert.equal(generate(root, { check: true }).changedPaths.length, 0);
    assert.equal(generate(root, { check: false }).changedPaths.length, 0);
    assert(
      readFileSync(join(root, "Draft/_sidebar.md"), "utf8").includes("(a.md)"),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("check mode does not write and invalid markers stop the whole write set", () => {
  const root = fixture();
  try {
    assert(generate(root, { check: true }).changedPaths.length > 0);
    assert(!existsSync(join(root, "Draft/Subject_Index.md")));
    writeFileSync(
      join(root, "Draft/a.md"),
      "# A\n<!-- nav:toc:start -->\n<!-- nav:toc:start -->\n<!-- nav:toc:end -->\n## Zebra\n",
    );
    assert(generate(root, { check: false }).diagnostics.length > 0);
    assert.equal(
      readFileSync(join(root, "README.md"), "utf8").includes("old"),
      true,
    );
    assert(!existsSync(join(root, "Draft/Subject_Index.md")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("invalid subject targets and duplicate canonical pages fail before writes", () => {
  const root = fixture();
  try {
    const path = join(root, "navigation/topics.json"),
      m = JSON.parse(readFileSync(path));
    m.pages[0].subjects[0].fragment = "missing";
    writeFileSync(path, JSON.stringify(m));
    assert(
      generate(root, { check: false }).diagnostics.some(
        (d) => d.code === "invalid-subject",
      ),
    );
    m.pages.push(m.pages[0]);
    writeFileSync(path, JSON.stringify(m));
    assert(
      generate(root, { check: false }).diagnostics.some(
        (d) => d.code === "duplicate-page",
      ),
    );
    assert(!existsSync(join(root, "Draft/_sidebar.md")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("an output symlink cannot read or overwrite bytes outside the repository", async () => {
  const { symlinkSync } = await import("node:fs");
  const root = fixture(),
    outside = mkdtempSync(join(process.cwd(), ".nav-test-"));
  try {
    writeFileSync(join(outside, "sentinel.md"), "External bytes must survive");
    symlinkSync(
      join(outside, "sentinel.md"),
      join(root, "Draft/Subject_Index.md"),
    );
    const result = generate(root, { check: false });
    assert(result.diagnostics.length > 0);
    assert.equal(
      readFileSync(join(outside, "sentinel.md"), "utf8"),
      "External bytes must survive",
    );
    assert(readFileSync(join(root, "README.md"), "utf8").includes("old"));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
