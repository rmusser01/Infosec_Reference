import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describeObject } from "../../tools/archive/storage.mjs";
import { recheckCapture } from "../../tools/archive/recheck.mjs";

test("missing replay evidence does not turn verified capture integrity into failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "archive-recheck-"));
  try {
    await mkdir(join(directory, "capture"));
    const object = join(directory, "capture", "fixture");
    await writeFile(object, "abc");
    const prior = {
      captureId: "recheck-1",
      requestedUrl: "https://example.org/",
      objects: [await describeObject(object)],
      storageState: "temporary",
    };
    const snapshot = {
      state: "article",
      url: prior.requestedUrl,
      text: "Readable article ".repeat(20),
      images: [],
    };
    await writeFile(join(directory, "attempt.json"), JSON.stringify(prior));
    await writeFile(
      join(directory, "capture/article.json"),
      JSON.stringify(snapshot),
    );
    // The external Docker verifier is covered separately by the real warcio/fixture pilot.
    const runtime = {
      verify: async (path) => {
        if (path.endsWith("replay")) throw Error("Missing replay");
        return {
          integrityState: "verified",
          records: [
            {
              url: snapshot.url,
              type: "response",
              status: 200,
              contentType: "text/html",
            },
            {
              url: "urn:text:" + snapshot.url,
              text: snapshot.text,
              type: "resource",
            },
          ],
        };
      },
    };
    const result = await recheckCapture(directory, { runtime });
    assert.equal(result.integrityState, "verified");
    assert.equal(result.captureState, "complete");
    assert.equal(result.replayState, "failed");
    assert.equal(result.storageState, "temporary");
    const replay = {
      integrityState: "verified",
      records: [
        {
          url: "urn:pageinfo:" + snapshot.url,
          text: JSON.stringify({
            comparison: { textMatch: 1 },
            urls: { [snapshot.url]: { status: 200 } },
          }),
        },
      ],
    };
    const passingRuntime = {
      verify: async (path) =>
        path.endsWith("replay") ? replay : runtime.verify(path),
    };
    for (const evidence of [
      { filtering: { blockedResponses: [{ kind: "budget-exceeded" }] } },
      { localBytes: 2000, storageCeilingBytes: 1000 },
    ]) {
      await writeFile(
        join(directory, "attempt.json"),
        JSON.stringify({ ...prior, captureState: "partial", ...evidence }),
      );
      assert.equal(
        (await recheckCapture(directory, { runtime: passingRuntime }))
          .captureState,
        "partial",
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
