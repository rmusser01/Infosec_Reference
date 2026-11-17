import { readFile, writeFile, rm, chmod, link, rename } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join, relative, resolve, sep } from "node:path";
import { filesBelow, directoryBytes } from "./runtime.mjs";
import { describeObject, verifyObjects } from "./storage.mjs";

export async function readCapture(directory) {
  try {
    return JSON.parse(await readFile(join(directory, "retained.json"), "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return JSON.parse(await readFile(join(directory, "attempt.json"), "utf8"));
}

export async function retainCapture(directory, attempt) {
  directory = resolve(directory);
  const files = await filesBelow(directory);
  // Verify the originals before discarding any independently generated bundles.
  if (attempt.objects.length) await verifyObjects(attempt.objects);
  const keep = files.filter((file) => {
    const name = relative(directory, file).split(sep).join("/");
    return (
      name.startsWith("capture/") &&
      (/\.(warc\.gz|cdxj)$/.test(name) || name === "capture/article.json")
    );
  });
  const objects = [];
  for (const file of keep) {
    objects.push({
      ...(await describeObject(file)),
      relativePath: relative(directory, file).split(sep).join("/"),
    });
    await chmod(file, 0o444);
  }
  const retained = {
    ...attempt,
    objects,
    storageState: objects.length ? "local" : attempt.storageState,
    retention: {
      version: 1,
      retainedAt: new Date().toISOString(),
      removedBytes: 0,
    },
    replayEvidenceSource: "recorded-offline-qa",
  };
  const remove = files.filter(
    (file) => !keep.includes(file) && relative(directory, file).includes(sep),
  );
  const before = await directoryBytes(directory);
  const publish = async (exclusive) => {
    const temporary = join(directory, ".retained-" + randomUUID() + ".json");
    try {
      await writeFile(temporary, JSON.stringify(retained, null, 2) + "\n", {
        flag: "wx",
      });
      if (exclusive) await link(temporary, join(directory, "retained.json"));
      else await rename(temporary, join(directory, "retained.json"));
    } finally {
      await rm(temporary, { force: true });
    }
  };
  // The new manifest is authoritative even if cleanup is interrupted; old records remain history.
  await publish(true);
  for (const file of remove) await rm(file);
  for (const dir of ["discovery", "replay", "state"])
    await rm(join(directory, dir), { recursive: true, force: true });
  retained.localBytes = await directoryBytes(directory);
  retained.retention.removedBytes = Math.max(0, before - retained.localBytes);
  await publish(false);
  return retained;
}
