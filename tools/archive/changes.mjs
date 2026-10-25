import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, appendFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { markdownFiles } from "../navigation/audit.mjs";
import { repositoryPath } from "../navigation/paths.mjs";
import { collectResources } from "../navigation/resources.mjs";
import { buildArchivePlan } from "./plan.mjs";
import { captureUrl } from "./capture.mjs";
import { verifyObjects } from "./storage.mjs";
import { directoryBytes } from "./runtime.mjs";
import { saveWayback } from "./wayback.mjs";
const execute = promisify(execFile);
const resourcePath = (path) =>
  (path === "README.md" ||
    (path.startsWith("Draft/") && path.endsWith(".md"))) &&
  !["Draft/_sidebar.md", "Draft/Subject_Index.md"].includes(path);
export async function addedResources(root, base, head) {
  const git = async (...args) =>
    (await execute("git", args, { cwd: root, maxBuffer: 32 * 1024 * 1024 }))
      .stdout;
  const documents = async (ref) => {
    if (!ref)
      return Promise.all(
        markdownFiles(root)
          .filter(resourcePath)
          .map(async (path) => ({
            path,
            source: await readFile(repositoryPath(root, path), "utf8"),
          })),
      );
    const sha = (
      await git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
    ).trim();
    const entries = (await git("ls-tree", "-rz", sha))
      .split("\0")
      .filter(Boolean);
    const rows = [];
    for (const entry of entries) {
      const [meta, path] = entry.split("\t");
      if (!resourcePath(path)) continue;
      if (!meta.startsWith("100644 blob ") && !meta.startsWith("100755 blob "))
        throw Error("Unsafe resource Git object: " + path);
      rows.push({ path, source: await git("show", sha + ":" + path) });
    }
    return rows;
  };
  const before = new Set(
    collectResources(await documents(base)).map((r) => r.url),
  );
  return collectResources(await documents(head)).filter(
    (r) => !before.has(r.url),
  );
}

async function readRows(path) {
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
export function waybackCatalog(rows) {
  const latest = new Map(rows.map((row) => [row.originalUrl, row]));
  const lines = [
    "# Archived references",
    "",
    "Generated from confirmed Save Page Now job results. Local captures and Wayback captures are verified separately.",
    "",
    "Only confirmed snapshots appear below; pending/failed jobs remain in `navigation/wayback-captures.jsonl`.",
    "",
  ];
  for (const row of [...latest.values()].sort((a, b) =>
    a.originalUrl.localeCompare(b.originalUrl),
  )) {
    if (row.state !== "saved") continue;
    // Reconstruct links from validated fields; never render a service-provided HTML/Markdown label.
    if (
      !/^\d{14}$/.test(row.timestamp) ||
      !/^https?:\/\//.test(row.originalUrl) ||
      !/^https?:\/\//.test(row.archivedUrl ?? row.originalUrl)
    )
      continue;
    const url = row.originalUrl
      .replaceAll(">", "%3E")
      .replaceAll("<", "%3C")
      .replaceAll("\n", "%0A")
      .replaceAll("\r", "%0D");
    const archivedUrl = (row.archivedUrl ?? row.originalUrl)
      .replaceAll(">", "%3E")
      .replaceAll("<", "%3C")
      .replaceAll("\n", "%0A")
      .replaceAll("\r", "%0D");
    lines.push(
      `- <${url}> — [Wayback snapshot ${row.timestamp}](<https://web.archive.org/web/${row.timestamp}/${archivedUrl}>)`,
    );
  }
  return lines.join("\n") + "\n";
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  for (const path of [
    "navigation/archive-captures.jsonl",
    "navigation/wayback-captures.jsonl",
    "navigation/archive-policy.json",
    "docs/archives/README.md",
  ])
    repositoryPath(process.cwd(), path, { allowMissing: true });
  const args = process.argv.slice(2);
  const value = (name, fallback) => {
    const i = args.indexOf(name);
    if (i < 0) return fallback;
    if (!args[i + 1] || args[i + 1].startsWith("--"))
      throw Error("Missing " + name);
    return args[i + 1];
  };
  const limit = Number(value("--limit", "3"));
  if (!Number.isInteger(limit) || limit < 1 || limit > 10)
    throw Error("Use --limit 1..10");
  const base = value("--base", "HEAD"),
    head = value("--head", null);
  const wayback = await readRows("navigation/wayback-captures.jsonl");
  const latest = new Map(wayback.map((r) => [r.originalUrl, r]));
  const rows = await addedResources(process.cwd(), base, head);
  if (args.includes("--resume")) {
    const urls = new Set(rows.map((r) => r.url));
    for (const row of latest.values())
      if (
        ["pending", "deferred"].includes(row.state) &&
        (!row.retryAt || Date.parse(row.retryAt) <= Date.now()) &&
        !urls.has(row.originalUrl)
      ) {
        rows.push({
          id: row.resourceId,
          url: row.originalUrl,
          source_references: row.sourceReferences ?? [],
        });
        urls.add(row.originalUrl);
      }
  }
  const plan = buildArchivePlan(rows);
  const output = resolve(
    value("--output", join("archive-data", "changes-" + randomUUID())),
  );
  await mkdir(output, { recursive: true, mode: 0o700 });
  await writeFile(
    join(output, "changes.json"),
    JSON.stringify({ base, head: head ?? "working-tree", ...plan }, null, 2) +
      "\n",
  );
  console.log(
    JSON.stringify({
      added: rows.length,
      queues: plan.summary?.queues,
      output,
    }),
  );
  if (!args.includes("--execute")) process.exit(0);
  const policy = JSON.parse(
    await readFile("navigation/archive-policy.json", "utf8"),
  );
  const captures = await readRows("navigation/archive-captures.jsonl");
  let processed = 0;
  for (const job of plan.jobs) {
    const previous = captures
      .filter((r) => r.originalUrl === job.originalUrl)
      .at(-1);
    const localReady =
      previous?.captureState === "complete" &&
      previous.integrityState === "verified" &&
      previous.replayState === "verified" &&
      (await verifyObjects(previous.objects).catch(() => false));
    const prior = latest.get(job.originalUrl);
    const localAttempted =
      localReady || (previous && previous.captureState !== "complete");
    if (
      prior?.retryAt &&
      Date.parse(prior.retryAt) > Date.now() &&
      (localAttempted || args.includes("--wayback-only"))
    )
      continue;
    if (
      (localAttempted || args.includes("--wayback-only")) &&
      ["saved", "uncertain", "rejected", "failed"].includes(prior?.state)
    )
      continue;
    if (processed++ >= limit) break;
    let local = localAttempted ? previous : null;
    if (!args.includes("--wayback-only") && !localAttempted) {
      const remaining =
        policy.pilotStorageCeilingBytes - (await directoryBytes(output));
      if (remaining < 1024 * 1024) break;
      local = await captureUrl(
        job,
        { ...policy, pilotStorageCeilingBytes: remaining },
        { directory: join(output, randomUUID()) },
      );
      await appendFile(
        "navigation/archive-captures.jsonl",
        JSON.stringify(local) + "\n",
      );
    }
    const saved = await saveWayback(job.originalUrl, {
      prior,
      finalUrl: local?.finalUrl,
      record: async (row) => {
        const entry = {
          ...row,
          resourceId: job.resourceId,
          sourceReferences: job.sourceReferences,
        };
        await appendFile(
          "navigation/wayback-captures.jsonl",
          JSON.stringify(entry) + "\n",
        );
        latest.set(job.originalUrl, entry);
      },
    });
    console.log(
      JSON.stringify({
        originalUrl: job.originalUrl,
        local: local?.captureState ?? "not-run",
        wayback: saved.state,
        archiveUrl: saved.archiveUrl,
      }),
    );
  }
  await mkdir("docs/archives", { recursive: true });
  await writeFile(
    "docs/archives/README.md",
    waybackCatalog([...latest.values()]),
  );
  await writeFile(
    join(output, "wayback-results.json"),
    JSON.stringify([...latest.values()], null, 2) + "\n",
  );
  await writeFile(
    join(output, "wayback-results.md"),
    waybackCatalog([...latest.values()]),
  );
  if (process.env.GITHUB_STEP_SUMMARY)
    await appendFile(
      process.env.GITHUB_STEP_SUMMARY,
      waybackCatalog([...latest.values()]),
    );
}
