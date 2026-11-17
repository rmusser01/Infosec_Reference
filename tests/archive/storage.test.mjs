import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyObjects, persistCapture } from "../../tools/archive/storage.mjs";

test("immutable storage verifies retrieval and a second copy, never overwrites an earlier capture", async () => {
  const root = mkdtempSync(join(tmpdir(), "archive-storage-"));
  try {
    const source = join(root, "object.warc.gz");
    writeFileSync(source, "abc");
    const attempt = {
      captureId: "capture-1",
      captureState: "complete",
      integrityState: "verified",
      replayState: "verified",
      objects: [
        {
          uri: pathToFileURL(source).href,
          bytes: 3,
          sha256:
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
      ],
    };
    assert.equal(await verifyObjects(attempt.objects), true);
    const stored = await persistCapture(attempt, {
      primary: join(root, "primary"),
      backup: join(root, "backup"),
    });
    assert.equal(stored.storageState, "copied");
    assert.equal(stored.copyState, "verified");
    assert.equal(stored.objects.length, 2);
    assert(
      stored.objects.every(
        (o) => readFileSync(new URL(o.uri), "utf8") === "abc",
      ),
    );
    await assert.rejects(
      persistCapture(attempt, {
        primary: join(root, "primary"),
        backup: join(root, "backup"),
      }),
    );
    assert.equal(readFileSync(source, "utf8"), "abc");
    await assert.rejects(
      persistCapture(attempt, {
        primary: join(root, "durable-primary"),
        backup: join(root, "durable-backup"),
        durable: true,
      }),
    );
    const indexed = {
      ...attempt,
      captureId: "indexed",
      objects: [
        {
          ...attempt.objects[0],
          relativePath: "capture/archive/example.warc.gz",
        },
      ],
    };
    const withPaths = await persistCapture(indexed, {
      primary: join(root, "paths-primary"),
      backup: join(root, "paths-backup"),
    });
    assert(
      withPaths.objects.every((o) =>
        o.uri.endsWith("/capture/archive/example.warc.gz"),
      ),
    );
    await assert.rejects(
      persistCapture(
        {
          ...indexed,
          captureId: "unsafe",
          objects: [{ ...indexed.objects[0], relativePath: "../escape" }],
        },
        {
          primary: join(root, "paths-primary"),
          backup: join(root, "paths-backup"),
        },
      ),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("checksum mismatch or failed backup cannot produce verified storage", async () => {
  const root = mkdtempSync(join(tmpdir(), "archive-storage-"));
  try {
    const file = join(root, "a");
    writeFileSync(file, "tampered");
    const attempt = {
      captureId: "capture-2",
      objects: [
        { uri: pathToFileURL(file).href, bytes: 3, sha256: "a".repeat(64) },
      ],
    };
    await assert.rejects(
      persistCapture(attempt, {
        primary: join(root, "primary"),
        backup: join(root, "backup"),
      }),
    );
    assert(!existsSync(join(root, "primary")));
    await assert.rejects(
      persistCapture(attempt, { primary: root, backup: root }),
    );
    writeFileSync(file, "abc");
    attempt.objects[0].sha256 =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const blocked = join(root, "not-a-directory");
    writeFileSync(blocked, "occupied");
    await assert.rejects(
      persistCapture(attempt, {
        primary: join(root, "primary"),
        backup: join(blocked, "backup"),
      }),
    );
    assert.equal(readFileSync(blocked, "utf8"), "occupied");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
