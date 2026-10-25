import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  rm,
  access,
  chmod,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describeObject, verifyObjects } from "../../tools/archive/storage.mjs";
import { retainCapture } from "../../tools/archive/retention.mjs";
import { recheckCapture } from "../../tools/archive/recheck.mjs";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";

test("interrupted final manifest replacement preserves the published manifest after QA cleanup", async () => {
  const root = await mkdtemp(join(tmpdir(), "archive-manifest-"));
  const original = fs.rename;
  try {
    await mkdir(join(root, "capture"));
    await mkdir(join(root, "replay"));
    await writeFile(join(root, "capture/article.warc.gz"), "original");
    await writeFile(join(root, "replay/qa.warc.gz"), "disposable");
    const objects = [
      {
        ...(await describeObject(join(root, "capture/article.warc.gz"))),
        relativePath: "capture/article.warc.gz",
      },
    ];
    fs.rename = async () => {
      throw Error("simulated interrupted metadata replacement");
    };
    syncBuiltinESMExports();
    await assert.rejects(
      retainCapture(root, {
        objects,
        captureId: "crash",
        replayState: "verified",
      }),
      /simulated interrupted/,
    );
    const manifest = JSON.parse(
      await readFile(join(root, "retained.json"), "utf8"),
    );
    await verifyObjects(manifest.objects);
    assert.equal(manifest.replayState, "verified");
    await assert.rejects(access(join(root, "replay/qa.warc.gz")));
  } finally {
    fs.rename = original;
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
});

test("compact retention removes bundles and QA but rechecks original text/figures and recorded QA", async () => {
  const root = await mkdtemp(join(tmpdir(), "archive-retain-"));
  try {
    const snapshot = {
      state: "article",
      url: "https://example.org/a",
      text: "Article ".repeat(30),
      images: [],
    };
    const names = [
      "capture/article.warc.gz",
      "capture/index.cdxj",
      "capture/article.wacz",
      "replay/qa.warc.gz",
      "state/mitmproxy-ca.pem",
    ];
    const objects = [];
    for (const name of names) {
      await mkdir(join(root, name, ".."), { recursive: true });
      await writeFile(join(root, name), "fixture bytes");
      if (!name.startsWith("state/"))
        objects.push({
          ...(await describeObject(join(root, name))),
          relativePath: name,
        });
    }
    await writeFile(
      join(root, "capture/article.json"),
      JSON.stringify(snapshot),
    );
    const prior = {
      captureId: "fixture",
      captureState: "complete",
      integrityState: "verified",
      replayState: "verified",
      storageState: "temporary",
      objects,
      replayEvidence: {
        comparison: { textMatch: 1 },
        urls: { [snapshot.url]: { status: 200 } },
      },
    };
    await writeFile(join(root, "attempt.json"), JSON.stringify(prior));
    const retained = await retainCapture(root, prior);
    await verifyObjects(retained.objects);
    assert.equal(retained.storageState, "local");
    assert(
      retained.objects.some(
        (o) => o.relativePath === "capture/article.warc.gz",
      ),
    );
    for (const name of [
      "capture/article.wacz",
      "replay/qa.warc.gz",
      "state/mitmproxy-ca.pem",
    ])
      await assert.rejects(access(join(root, name)));
    const runtime = {
      verify: async (path) => {
        assert(path.endsWith("/capture"), "do not pretend to rerun removed QA");
        return {
          integrityState: "verified",
          records: [
            {
              url: snapshot.url,
              type: "response",
              status: 200,
              contentType: "text/html",
            },
            { url: "urn:text:" + snapshot.url, text: snapshot.text },
          ],
        };
      },
    };
    const checked = await recheckCapture(root, { runtime });
    assert.equal(checked.captureState, "complete");
    assert.equal(checked.replayState, "verified");
    assert.equal(checked.replayEvidenceSource, "recorded-offline-qa");
    assert.equal(
      JSON.parse(await readFile(join(root, "attempt.json"), "utf8")).objects
        .length,
      4,
      "original attempt remains history",
    );
    await chmod(join(root, "capture/article.warc.gz"), 0o644);
    await writeFile(join(root, "capture/article.warc.gz"), "changed");
    const failed = await recheckCapture(root, { runtime });
    assert.equal(failed.integrityState, "failed");
    assert.notEqual(failed.replayState, "verified");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
