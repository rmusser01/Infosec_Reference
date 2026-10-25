import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyResource } from "../navigation/resources.mjs";
export function buildArchivePlan(
  records,
  { evidence = [], priorCaptures = [] } = {},
) {
  const observations = new Map(
    evidence.map((e) => [e.originalUrl?.split("#")[0], e]),
  );
  const complete = new Set(
    priorCaptures
      .filter(
        (c) =>
          c.captureState === "complete" &&
          c.storageState === "verified" &&
          c.integrityState === "verified" &&
          c.replayState === "verified" &&
          c.objects?.length &&
          c.objects.every(
            (o) => o.uri && o.bytes > 0 && /^[a-f\d]{64}$/i.test(o.sha256),
          ),
      )
      .map((c) => c.originalUrl?.split("#")[0]),
  );
  const jobs = records.map((record) => {
    const observed = observations.get(record.url),
      classification = classifyResource(record, observed ?? {});
    const job = {
      resourceId: record.id,
      originalUrl: record.url,
      sourceReferences: record.source_references,
      classification,
      queue: classification.processingQueue,
      status: "pending",
      availabilityState: observed?.availabilityState ?? "not-checked",
    };
    if (observed && observed.availabilityState !== "reachable")
      job.status = "needs-review";
    if (complete.has(record.url) && job.queue === "web_capture")
      job.status = "already-preserved";
    if (job.queue === "web_capture")
      job.capturePolicy = {
        format: "warc.gz",
        images: "article-only",
        standaloneMedia: "queue-only",
        scripts: "required-rendering-only",
        publication: "none",
      };
    return job;
  });
  const counts = {};
  for (const job of jobs) counts[job.queue] = (counts[job.queue] ?? 0) + 1;
  return {
    version: 1,
    summary: {
      total: jobs.length,
      alreadyPreserved: jobs.filter((j) => j.status === "already-preserved")
        .length,
      queues: counts,
    },
    jobs,
  };
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
  const inventory = value(
      "--inventory",
      "docs/inventories/resource-inventory.jsonl",
    ),
    evidencePath = value("--evidence", null),
    capturePath = value("--captures", "navigation/archive-captures.jsonl");
  const lines = (path) =>
    existsSync(path)
      ? readFileSync(path, "utf8").split("\n").filter(Boolean).map(JSON.parse)
      : [];
  const evidence = evidencePath
    ? JSON.parse(readFileSync(evidencePath, "utf8")).results
    : [];
  if (!existsSync(inventory)) throw Error("Inventory not found: " + inventory);
  const plan = buildArchivePlan(lines(inventory), {
    evidence,
    priorCaptures: lines(capturePath),
  });
  writeFileSync(
    value("--output", "archive-plan.json"),
    JSON.stringify(plan, null, 2) + "\n",
  );
  console.log(JSON.stringify(plan.summary, null, 2));
}
