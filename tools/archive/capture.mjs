import {
  readFile,
  writeFile,
  mkdir,
  appendFile,
  chmod,
} from "node:fs/promises";
import { resolve, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { BrowsertrixRuntime, filesBelow, directoryBytes } from "./runtime.mjs";
import { describeObject, verifyObjects, persistCapture } from "./storage.mjs";
import { classifyResource } from "../navigation/resources.mjs";
import { buildArchivePlan } from "./plan.mjs";
import { retainCapture } from "./retention.mjs";

const normalized = (text) => (text ?? "").replace(/\s/g, "");
export function processingQueues(snapshot, job) {
  const rows = [];
  for (const item of [
    ...snapshot.links.map((url) => ({ url })),
    ...snapshot.embeds,
  ]) {
    const classification = classifyResource({ url: item.url });
    if (!item.kind && ["unknown", "webpage"].includes(classification.type))
      continue;
    if (snapshot.images.includes(item.url)) continue;
    rows.push({
      url: item.url,
      queue:
        item.kind === "video"
          ? "video"
          : item.kind === "audio"
            ? "other_nontext"
            : classification.processingQueue,
      classification,
      parentUrl: snapshot.url,
      parentResourceId: job.resourceId,
      sourceReferences: job.sourceReferences,
    });
  }
  return rows;
}
export function verifyCapture(snapshot, integrity, qa) {
  const records = integrity.records ?? [];
  const html = records.find(
    (r) =>
      r.url === snapshot.url &&
      r.type === "response" &&
      r.status >= 200 &&
      r.status < 300 &&
      /^(text\/html|application\/xhtml\+xml)/i.test(r.contentType),
  );
  const text = records.find(
    (r) => r.url === "urn:text:" + (snapshot.requestedUrl ?? snapshot.url),
  )?.text;
  const missingImages = snapshot.images.filter(
    (url) =>
      !records.some(
        (r) =>
          r.url === url &&
          r.type === "response" &&
          r.status >= 200 &&
          r.status < 300 &&
          /^image\//i.test(r.contentType),
      ),
  );
  const contentVerified = Boolean(
    snapshot.state === "article" &&
      html &&
      normalized(snapshot.text) &&
      normalized(text).includes(normalized(snapshot.text)) &&
      !snapshot.imageFailures?.length &&
      !missingImages.length,
  );
  const replayed = (url) =>
    qa?.urls?.[url]?.status >= 200 && qa?.urls?.[url]?.status < 300;
  const replayState = !qa
    ? "not-tested"
    : qa.comparison?.textMatch === 1 &&
        replayed(snapshot.url) &&
        snapshot.images.every(replayed)
      ? "verified"
      : "partial";
  return {
    integrityState: integrity.integrityState,
    contentState: contentVerified ? "verified" : "needs-review",
    replayState,
    missingImages,
    captureState:
      snapshot.state === "access-wall"
        ? "inaccessible"
        : contentVerified && integrity.integrityState === "verified"
          ? "complete"
          : "partial",
  };
}

export function enforceCaptureScope(attempt) {
  const blocked =
    attempt.filtering?.blockedResponses?.length ||
    attempt.policyState === "partial" ||
    attempt.localBytes > attempt.storageCeilingBytes;
  return {
    ...attempt,
    policyState: blocked ? "partial" : "verified",
    captureState:
      blocked && attempt.captureState === "complete"
        ? "partial"
        : attempt.captureState,
  };
}

async function jsonLines(path) {
  try {
    return (await readFile(path, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

export async function captureUrl(job, policy, { directory, runtime } = {}) {
  let attempt = {
    captureId: randomUUID(),
    resourceId: job.resourceId,
    sourceReferences: job.sourceReferences,
    originalUrl: job.originalUrl,
    capturedAt: new Date().toISOString(),
    availabilityState: "not-checked",
    captureState: "deferred",
    integrityState: "not-tested",
    contentState: "not-tested",
    replayState: "not-tested",
    storageState: "temporary",
    storageCeilingBytes: policy.pilotStorageCeilingBytes,
    objects: [],
    warcRecordIds: [],
    redirectChain: [],
  };
  if (!["web_capture", "type_confirmation"].includes(job.queue))
    return { ...attempt, processingQueue: job.queue };
  const requested = new URL(job.originalUrl);
  if (
    !["http:", "https:"].includes(requested.protocol) ||
    requested.username ||
    requested.password ||
    !["", "80", "443"].includes(requested.port)
  )
    throw Error("Unsafe capture URL");
  requested.hash = "";
  attempt.requestedUrl = requested.href;
  directory = resolve(directory ?? join("archive-data", attempt.captureId));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  runtime ??= new BrowsertrixRuntime(directory, policy);
  try {
    await runtime.start();
    attempt.toolVersion = runtime.runtimeIds;
    await runtime.configure([requested.href]);
    const discovery = await runtime.run("discovery", requested.href);
    const article = JSON.parse(
      await readFile(join(discovery, "article.json"), "utf8"),
    );
    attempt.finalUrl = article.url;
    attempt.discoveredQueues = processingQueues(article, job);
    if (article.state !== "article") {
      attempt.captureState =
        article.state === "access-wall" ? "inaccessible" : "deferred";
      attempt.contentState = article.state;
    } else {
      const captureSeed = new URL(article.url);
      if (
        !["http:", "https:"].includes(captureSeed.protocol) ||
        captureSeed.username ||
        captureSeed.password ||
        !["", "80", "443"].includes(captureSeed.port)
      )
        throw Error("Unsafe final capture URL");
      captureSeed.hash = "";
      attempt.captureSeedUrl = captureSeed.href;
      await runtime.configure([requested.href, article.url], article.images);
      // Discovery keeps redirect provenance; direct capture avoids recorder-omitted redirect bodies.
      const capture = await runtime.run("capture", attempt.captureSeedUrl);
      const captured = JSON.parse(
        await readFile(join(capture, "article.json"), "utf8"),
      );
      const integrity = await runtime.verify(capture);
      attempt.warcRecordIds = integrity.records.map((r) => r.id);
      let qa = null;
      try {
        const replay = await runtime.run("replay");
        const verifiedReplay = await runtime.verify(replay);
        qa =
          verifiedReplay.records
            .filter(
              (r) =>
                r.url ===
                "urn:pageinfo:" + (captured.requestedUrl ?? captured.url),
            )
            .map((r) => JSON.parse(r.text))
            .find((p) => p.comparison) ?? {};
        attempt.replayEvidence = qa;
      } catch (error) {
        attempt.replayError = error.message;
      }
      Object.assign(attempt, verifyCapture(captured, integrity, qa));
      if (attempt.replayError) attempt.replayState = "failed";
      for (const file of await filesBelow(directory)) {
        if (/\.(warc\.gz|wacz|cdxj)$/.test(file)) {
          attempt.objects.push({
            ...(await describeObject(file)),
            relativePath: relative(directory, file).split(sep).join("/"),
          });
          await chmod(file, 0o444);
        }
      }
    }
  } catch (error) {
    attempt.captureState = "failed";
    attempt.error = error.message;
  } finally {
    await runtime.close();
  }
  const events = await jsonLines(join(directory, "state/events.jsonl"));
  attempt.redirectChain = events
    .filter((e) => e.kind === "redirect")
    .map((e) => ({ from: e.url, to: e.target, status: e.status }));
  const response = events
    .filter(
      (e) =>
        ["response", "queued-response"].includes(e.kind) &&
        [attempt.requestedUrl, attempt.finalUrl].includes(e.url),
    )
    .at(-1);
  if (response) {
    attempt.httpStatus = response.status;
    attempt.contentType = response.contentType;
    attempt.availabilityState =
      response.status >= 200 && response.status < 300
        ? "reachable"
        : [404, 410].includes(response.status)
          ? "missing"
          : "uncertain";
    const classification = classifyResource(
      { url: job.originalUrl },
      {
        httpStatus: response.status,
        contentType: response.contentType,
        availabilityState: attempt.availabilityState,
        finalUrl: attempt.finalUrl ?? response.url,
      },
    );
    if (classification.processingQueue !== "web_capture")
      attempt.processingQueue = classification.processingQueue;
    if (
      ["pdf", "video", "other_nontext"].includes(classification.processingQueue)
    ) {
      attempt.captureState = "deferred";
      attempt.routingNote =
        attempt.error ?? "Non-text resource queued before capture";
      delete attempt.error;
    }
  }
  attempt.filtering = {
    blockedRequests: events.filter((e) => e.kind === "blocked-request"),
    blockedResponses: events.filter((e) =>
      ["blocked-response", "blocked-network", "budget-exceeded"].includes(
        e.kind,
      ),
    ),
  };
  if (
    attempt.filtering.blockedResponses.length &&
    attempt.captureState === "complete"
  )
    attempt.captureState = "partial";
  attempt.discoveredQueues = [
    ...(attempt.discoveredQueues ?? []),
    ...events
      .filter((e) => e.kind === "queued-response")
      .map((e) => ({
        url: e.url,
        contentType: e.contentType,
        queue: classifyResource(
          { url: e.url },
          {
            httpStatus: e.status,
            contentType: e.contentType,
            availabilityState:
              e.status >= 200 && e.status < 300 ? "reachable" : "uncertain",
          },
        ).processingQueue,
        parentResourceId: job.resourceId,
        sourceReferences: job.sourceReferences,
      })),
  ];
  attempt.localBytes = await directoryBytes(directory);
  if (attempt.localBytes > policy.pilotStorageCeilingBytes) {
    attempt.captureState = "partial";
    attempt.error = "Pilot storage ceiling exceeded";
  }
  attempt = enforceCaptureScope(attempt);
  await writeFile(
    join(directory, "attempt.json"),
    JSON.stringify(attempt, null, 2) + "\n",
    { flag: "wx" },
  );
  return retainCapture(directory, attempt);
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const args = process.argv.slice(2),
    value = (name, fallback) => {
      const i = args.indexOf(name);
      return i < 0 ? fallback : args[i + 1];
    };
  const limit = Number(value("--limit", "3")),
    offset = Number(value("--offset", "0"));
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 10 ||
    !Number.isInteger(offset) ||
    offset < 0
  )
    throw Error("Pilot requires --limit 1..10 and nonnegative --offset");
  const policy = JSON.parse(
    await readFile("navigation/archive-policy.json", "utf8"),
  );
  const inventory = await jsonLines(
    "docs/inventories/resource-inventory.jsonl",
  );
  const requested = value("--url", null);
  const records = requested
    ? inventory.filter((r) => r.url === requested)
    : inventory.slice(offset, offset + limit);
  if (!records.length)
    throw Error("Select an existing inventory URL or valid offset");
  const manifest = "navigation/archive-captures.jsonl";
  const prior = await jsonLines(manifest);
  const plan = buildArchivePlan(records, { priorCaptures: prior });
  const batch = resolve(
    value("--output", join("archive-data", "pilot-" + randomUUID())),
  );
  await mkdir(batch, { recursive: true, mode: 0o700 });
  const results = [];
  for (const job of plan.jobs) {
    let attempt;
    const previous = prior
      .filter(
        (p) =>
          p.originalUrl === job.originalUrl &&
          p.storageState === "verified" &&
          p.captureState === "complete" &&
          p.replayState === "verified" &&
          p.integrityState === "verified",
      )
      .at(-1);
    if (
      previous &&
      (await verifyObjects(previous.objects).catch(() => false))
    ) {
      results.push({
        originalUrl: job.originalUrl,
        captureState: "already-preserved",
      });
      continue;
    }
    const remaining =
      policy.pilotStorageCeilingBytes - (await directoryBytes(batch));
    if (remaining < 1024 * 1024) {
      results.push({
        originalUrl: job.originalUrl,
        captureState: "deferred",
        reason: "Pilot storage ceiling",
      });
      continue;
    }
    attempt = await captureUrl(
      job,
      { ...policy, pilotStorageCeilingBytes: remaining },
      { directory: join(batch, randomUUID()) },
    );
    const destination = policy.durableDestination ?? {};
    const primary = value("--primary", destination.primary ?? null),
      backup = value("--backup", destination.backup ?? null);
    if (primary || backup) {
      try {
        attempt = await persistCapture(attempt, {
          primary,
          backup,
          durable:
            destination.confirmedDurable === true &&
            resolve(primary) === resolve(destination.primary) &&
            resolve(backup) === resolve(destination.backup),
        });
      } catch (error) {
        attempt.storageState = "failed";
        attempt.storageError = error.message;
      }
    }
    await appendFile(manifest, JSON.stringify(attempt) + "\n");
    results.push({
      originalUrl: attempt.originalUrl,
      captureState: attempt.captureState,
      replayState: attempt.replayState,
      storageState: attempt.storageState,
      localBytes: attempt.localBytes,
    });
    console.log(JSON.stringify(results.at(-1)));
  }
  await writeFile(
    join(batch, "report.json"),
    JSON.stringify(
      { totalInventory: inventory.length, selected: records.length, results },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
}
