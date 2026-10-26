import { readFile, writeFile, appendFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { verifyObjects } from "./storage.mjs";
import { BrowsertrixRuntime } from "./runtime.mjs";
import { verifyCapture, enforceCaptureScope } from "./capture.mjs";
import { readCapture } from "./retention.mjs";

export async function recheckCapture(
  directory,
  { runtime = new BrowsertrixRuntime(directory, {}) } = {},
) {
  const prior = await readCapture(directory);
  const attempt = { ...prior, verifiedAt: new Date().toISOString() };
  let snapshot, integrity;
  try {
    await verifyObjects(prior.objects);
    integrity = await runtime.verify(join(directory, "capture"));
    snapshot = JSON.parse(
      await readFile(join(directory, "capture/article.json"), "utf8"),
    );
    snapshot.requestedUrl ??= prior.captureSeedUrl ?? prior.requestedUrl;
    Object.assign(attempt, verifyCapture(snapshot, integrity, null));
  } catch (error) {
    return {
      ...attempt,
      integrityState: "failed",
      replayState: "not-tested",
      captureState: "partial",
      verificationError: error.message,
    };
  }
  if (prior.retention?.version === 1) {
    Object.assign(
      attempt,
      verifyCapture(snapshot, integrity, prior.replayEvidence ?? null),
      {
        replayEvidenceSource: "recorded-offline-qa",
      },
    );
    return enforceCaptureScope(attempt);
  }
  try {
    const replay = await runtime.verify(join(directory, "replay"));
    const qa =
      replay.records
        .filter(
          (r) =>
            r.url === "urn:pageinfo:" + (snapshot.requestedUrl ?? snapshot.url),
        )
        .map((r) => JSON.parse(r.text))
        .find((p) => p.comparison) ?? {};
    Object.assign(attempt, verifyCapture(snapshot, integrity, qa), {
      replayEvidence: qa,
    });
  } catch (error) {
    attempt.replayState = "failed";
    attempt.replayError = error.message;
  }
  return enforceCaptureScope(attempt);
}
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  if (!process.argv[2]) throw Error("Provide a local capture directory");
  const directory = resolve(process.argv[2]);
  const attempt = await recheckCapture(directory);
  await writeFile(
    join(directory, "verification-" + randomUUID() + ".json"),
    JSON.stringify(attempt, null, 2) + "\n",
    { flag: "wx" },
  );
  await appendFile(
    "navigation/archive-captures.jsonl",
    JSON.stringify(attempt) + "\n",
  );
  console.log(
    JSON.stringify({
      captureId: attempt.captureId,
      captureState: attempt.captureState,
      integrityState: attempt.integrityState,
      replayState: attempt.replayState,
      storageState: attempt.storageState,
    }),
  );
}
