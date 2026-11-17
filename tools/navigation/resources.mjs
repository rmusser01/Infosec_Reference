import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { repositoryPath } from "./paths.mjs";
import { parseDocument } from "./parse.mjs";
import { markdownFiles } from "./audit.mjs";
const decode = (value) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};
const videoHosts = new Set([
  "youtube.com",
  "www.youtube.com",
  "youtu.be",
  "vimeo.com",
  "www.vimeo.com",
  "player.vimeo.com",
  "dailymotion.com",
  "www.dailymotion.com",
  "asciinema.org",
]);
const extensions = {
  pdf: "pdf",
  mp4: "video",
  webm: "video",
  mov: "video",
  mkv: "video",
  avi: "video",
  m4v: "video",
  mp3: "audio",
  wav: "audio",
  ogg: "audio",
  m4a: "audio",
  flac: "audio",
  ppt: "slides",
  pptx: "slides",
  odp: "slides",
  doc: "document",
  docx: "document",
  odt: "document",
  epub: "ebook",
  mobi: "ebook",
  xls: "spreadsheet",
  xlsx: "spreadsheet",
  csv: "dataset",
  tsv: "dataset",
  pcap: "packet_capture",
  pcapng: "packet_capture",
  cap: "packet_capture",
  zip: "archive",
  gz: "archive",
  bz2: "archive",
  xz: "archive",
  "7z": "archive",
  rar: "archive",
  tgz: "archive",
  iso: "disk_image",
  ova: "virtual_machine",
  ovf: "virtual_machine",
  exe: "binary",
  msi: "binary",
  apk: "binary",
  dmg: "binary",
  deb: "binary",
  rpm: "binary",
  swf: "interactive_media",
  png: "standalone_image",
  jpg: "standalone_image",
  jpeg: "standalone_image",
  gif: "standalone_image",
  svg: "standalone_image",
  webp: "standalone_image",
};
export function classifyResource(reference, responseEvidence = {}) {
  const url = typeof reference === "string" ? reference : reference.url;
  const usable =
    (responseEvidence.httpStatus === undefined ||
      (responseEvidence.httpStatus >= 200 &&
        responseEvidence.httpStatus < 300)) &&
    (!responseEvidence.availabilityState ||
      responseEvidence.availabilityState === "reachable");
  const mime = (usable ? (responseEvidence.contentType ?? "") : "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  let parsed;
  try {
    parsed = new URL(usable ? (responseEvidence.finalUrl ?? url) : url);
  } catch {
    return {
      type: "unknown",
      confidence: "unknown",
      evidence: "Invalid URL",
      processingQueue: "type_confirmation",
    };
  }
  let type = "unknown",
    confidence = "unknown",
    evidence = "Response/content inspection pending.";
  const knownVideo = videoHosts.has(parsed.hostname);
  if (mime === "application/pdf") {
    type = "pdf";
    confidence = "confirmed";
    evidence = "Response Content-Type application/pdf.";
  } else if (mime.startsWith("video/")) {
    type = "video";
    confidence = "confirmed";
    evidence = "Response video Content-Type.";
  } else if (mime.startsWith("audio/")) {
    type = "audio";
    confidence = "confirmed";
    evidence = "Response audio Content-Type.";
  } else if (mime.startsWith("image/")) {
    type = "standalone_image";
    confidence = "confirmed";
    evidence = "Response image Content-Type.";
  } else if (
    (mime === "text/html" || mime === "application/xhtml+xml") &&
    !knownVideo
  ) {
    type = "webpage";
    confidence = "confirmed";
    evidence = "Response HTML Content-Type.";
  } else if (knownVideo) {
    type = "video";
    confidence = "candidate";
    evidence =
      "Video/session host; may identify a channel, playlist, or landing page.";
  } else {
    const suffix = decode(parsed.pathname)
      .match(/\.([a-z\d]+)$/i)?.[1]
      ?.toLowerCase();
    if (extensions[suffix]) {
      type = extensions[suffix];
      confidence = "candidate";
      evidence = `URL extension .${suffix}; content inspection pending.`;
    } else if (/\.pdf(?:$|[&?#])/i.test(decode(parsed.search))) {
      type = "pdf";
      confidence = "candidate";
      evidence = "PDF filename in query; content inspection pending.";
    }
  }
  return {
    type,
    confidence,
    evidence,
    processingQueue:
      type === "unknown"
        ? "type_confirmation"
        : type === "webpage"
          ? "web_capture"
          : ["pdf", "video"].includes(type)
            ? type
            : "other_nontext",
  };
}
export function collectResources(documents, progress = {}) {
  const records = new Map();
  for (const { path, source, parsed } of documents)
    for (const link of (parsed ?? parseDocument(source, path)).links) {
      if (link.kind === "image" || !/^https?:\/\//i.test(link.url)) continue;
      const url = link.url.split("#")[0];
      const classified = classifyResource({ url });
      const sourceRef = {
        path,
        line: link.line,
        original_url: link.url,
        label: link.label || null,
      };
      if (!records.has(url))
        records.set(url, {
          id: createHash("sha256").update(url).digest("hex").slice(0, 20),
          url,
          type_candidate: classified.type,
          classification_status:
            classified.confidence === "confirmed" ? "confirmed" : "unverified",
          classification_evidence: classified.evidence,
          processing_queue: classified.processingQueue,
          processing_status: "pending",
          source_references: [],
        });
      records.get(url).source_references.push(sourceRef);
    }
  for (const row of records.values()) {
    const status = progress[row.id]?.processing_status;
    if (
      status &&
      ![
        "pending",
        "acquired",
        "extracted",
        "indexed",
        "failed",
        "deferred",
      ].includes(status)
    )
      throw new Error("Invalid processing status for " + row.id);
    if (status) row.processing_status = status;
  }
  return [...records.values()].sort((a, b) =>
    a.url < b.url ? -1 : a.url > b.url ? 1 : 0,
  );
}
export function generateResources(root) {
  const progressPath = resolve(root, "navigation/resource-progress.json");
  const progress = existsSync(progressPath)
    ? JSON.parse(
        readFileSync(
          repositoryPath(root, "navigation/resource-progress.json"),
          "utf8",
        ),
      )
    : {};
  const rows = collectResources(
    markdownFiles(root)
      .filter(
        (p) => p !== "Draft/_sidebar.md" && p !== "Draft/Subject_Index.md",
      )
      .map((path) => ({
        path,
        source: readFileSync(repositoryPath(root, path), "utf8"),
      })),
    progress,
  );
  const out = repositoryPath(root, "docs/inventories", {
    allowMissing: true,
    kind: "directory",
  });
  mkdirSync(out, { recursive: true });
  for (const name of [
    "resource-inventory.jsonl",
    "pdfs.md",
    "videos.md",
    "other-nontext.md",
  ])
    repositoryPath(root, "docs/inventories/" + name, { allowMissing: true });
  writeFileSync(
    resolve(out, "resource-inventory.jsonl"),
    rows.map((r) => JSON.stringify(r)).join("\n") + "\n",
  );
  const counts = {};
  for (const [type, name, title] of [
    ["pdf", "pdfs.md", "PDFs"],
    ["video", "videos.md", "Videos"],
    ["other_nontext", "other-nontext.md", "Other non-text resources"],
  ]) {
    const selected = rows.filter((r) => r.processing_queue === type);
    counts[type] = selected.length;
    const lines = [
      `# ${title} processing inventory`,
      "",
      "<!-- Generated by npm run resources:generate; do not edit this view. -->",
      "",
      `${selected.length} unique candidate URLs. Types are provisional until response/content verification.`,
      "",
      "[Machine-readable records and all source references](resource-inventory.jsonl). This generator performs no downloads, extraction, or indexing.",
      "",
    ];
    for (const row of selected) {
      const ref = row.source_references[0];
      const label = (ref.label ?? row.url)
        .replace(/[\r\n]/g, " ")
        .replace(/([\\*\[\]])/g, "\\$1");
      lines.push(
        `- **${label}**`,
        `  - URL: <${row.url.replaceAll(">", "%3E")}>`,
        `  - Candidate type: ${row.type_candidate}; status: ${row.classification_status} / ${row.processing_status}.`,
        `  - Source: \`${ref.path}:${ref.line}\`; references: ${row.source_references.length}.`,
        `  - ID: \`${row.id}\`.`,
      );
    }
    writeFileSync(resolve(out, name), lines.join("\n") + "\n");
  }
  return {
    total: rows.length,
    ...counts,
    unknown: rows.filter((r) => r.type_candidate === "unknown").length,
  };
}
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
)
  console.log(JSON.stringify(generateResources(process.cwd()), null, 2));
