import assert from "node:assert/strict";
import { mkdir, readFile, writeFile, rm, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { BrowsertrixRuntime, docker } from "../../tools/archive/runtime.mjs";
import { captureUrl } from "../../tools/archive/capture.mjs";
import { recheckCapture } from "../../tools/archive/recheck.mjs";
import { filesBelow } from "../../tools/archive/runtime.mjs";

const directory = resolve("archive-data/fixture-pilot-" + Date.now());
await mkdir(directory, { recursive: true });
await docker(
  "build",
  "-f",
  "tests/archive/Fixture.Dockerfile",
  "-t",
  "infosec-archive-fixtures:local",
  "tests/archive",
);
const images = {
  ...JSON.parse(await readFile("navigation/archive-runtime.json", "utf8")),
  proxyImage: "infosec-archive-fixtures:local",
};
const policy = JSON.parse(
  await readFile("navigation/archive-policy.json", "utf8"),
);
const results = [];
try {
  for (const path of process.argv.slice(2).length
    ? process.argv.slice(2)
    : [
        "article",
        "lazy",
        "blogger",
        "legacy-post",
        "javascript",
        "redirect",
        "redirect-body",
        "challenge",
        "private",
        "mislabeled",
        "redirect-media",
      ]) {
    const target = join(directory, path);
    const runtime = new BrowsertrixRuntime(target, policy, images);
    const attempt = await captureUrl(
      {
        resourceId: path,
        originalUrl: "https://archive-fixture.invalid/" + path,
        sourceReferences: [
          {
            path: "test-fixture",
            original_url: "https://archive-fixture.invalid/" + path + "#one",
          },
        ],
        queue: "type_confirmation",
      },
      policy,
      { directory: target, runtime },
    );
    results.push(attempt);
    console.log(
      JSON.stringify({
        path,
        capture: attempt.captureState,
        integrity: attempt.integrityState,
        replay: attempt.replayState,
        error: attempt.error,
      }),
    );
    if (
      [
        "article",
        "lazy",
        "blogger",
        "legacy-post",
        "javascript",
        "redirect",
        "redirect-body",
      ].includes(path)
    ) {
      assert.equal(attempt.captureState, "complete");
      assert.equal(attempt.integrityState, "verified");
      assert.equal(attempt.replayState, "verified");
      assert.equal(attempt.storageState, "local");
      assert(
        !(await filesBelow(target)).some(
          (p) =>
            p.endsWith(".wacz") ||
            p.includes("/replay/") ||
            p.includes("/state/"),
        ),
      );
      const checked = await recheckCapture(target, { runtime });
      assert.equal(checked.integrityState, "verified");
      assert.equal(checked.replayState, "verified");
      assert.equal(checked.replayEvidenceSource, "recorded-offline-qa");
      const proof = await runtime.verify(join(target, "capture"));
      assert(
        proof.records.some(
          (r) =>
            r.url === "https://archive-fixture.invalid/figure.png" &&
            r.contentType === "image/png",
        ),
      );
      assert(
        !proof.records.some((r) =>
          /\/(advert|logo)\.png|movie\.mp4|paper\.pdf/.test(r.url),
        ),
      );
    }
    if (["redirect", "redirect-body"].includes(path))
      assert(
        attempt.redirectChain.some(
          (r) => r.to === "https://archive-fixture.invalid/article",
        ),
      );
    if (path === "challenge")
      assert.equal(attempt.captureState, "inaccessible");
    if (path === "private") {
      assert.notEqual(attempt.captureState, "complete");
      assert(
        attempt.filtering.blockedResponses.some(
          (r) => r.kind === "blocked-network",
        ),
      );
    }
    if (path === "mislabeled") {
      assert.equal(attempt.captureState, "deferred");
      assert.equal(attempt.processingQueue, "pdf");
      assert.equal(attempt.objects.length, 0);
    }
    if (path === "redirect-media") {
      assert.notEqual(attempt.captureState, "complete");
      assert(
        attempt.filtering.blockedResponses.some(
          (e) => e.reason === "Non-text or unknown redirect body",
        ),
      );
      assert.equal(attempt.objects.length, 0);
    }
  }
} finally {
  await writeFile(
    join(directory, "report.json"),
    JSON.stringify({ fixturePayloadsDiscarded: true, results }, null, 2) + "\n",
  );
  for (const entry of await readdir(directory, { withFileTypes: true }))
    if (entry.isDirectory())
      await rm(join(directory, entry.name), { recursive: true, force: true });
}
console.log("Verified fixture pilot: " + directory);
