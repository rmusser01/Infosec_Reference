import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { repositoryPath } from "./paths.mjs";
import { parseDocument } from "./parse.mjs";
import { resolveInternalLink } from "./resolve.mjs";
export function markdownFiles(root) {
  const files = existsSync(join(root, "README.md")) ? ["README.md"] : [];
  if (files.length) repositoryPath(root, "README.md");
  const visit = (dir) => {
    for (const entry of readdirSync(
      repositoryPath(root, dir, { kind: "directory" }),
      {
        withFileTypes: true,
      },
    ).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const path = dir + "/" + entry.name;
      if (entry.isSymbolicLink() && entry.name.endsWith(".md"))
        throw new Error("Unsafe Markdown symlink: " + path);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith(".md")) files.push(path);
    }
  };
  if (existsSync(join(root, "Draft"))) visit("Draft");
  return files;
}
export function audit(root) {
  const documents = new Map(
    markdownFiles(root).map((path) => [
      path,
      parseDocument(readFileSync(repositoryPath(root, path), "utf8"), path),
    ]),
  );
  const findings = [],
    inbound = new Set();
  let linkCount = 0;
  for (const [path, doc] of documents) {
    findings.push(...doc.issues);
    const seen = new Set();
    for (const anchor of doc.anchors) {
      if (seen.has(anchor.fragment))
        findings.push({
          code: "duplicate-anchor",
          path,
          line: anchor.line,
          target: anchor.fragment,
          severity: "error",
        });
      seen.add(anchor.fragment);
    }
    const destinations = new Map();
    for (const link of doc.links) {
      linkCount++;
      const resolved = resolveInternalLink(root, path, link.url, documents);
      if (resolved.kind === "error")
        findings.push({
          code: resolved.code,
          path,
          line: link.line,
          target: link.url,
          severity: "error",
        });
      if (resolved.kind === "internal" || resolved.kind === "directory") {
        if (resolved.path !== path) inbound.add(resolved.path);
        const key = resolved.path + "#" + resolved.fragment;
        if (destinations.has(key) && link.kind === "link")
          findings.push({
            code: "repeated-destination",
            path,
            line: link.line,
            target: link.url,
            severity: "warning",
          });
        destinations.set(key, true);
      }
    }
  }
  for (const path of documents.keys())
    if (path !== "README.md" && !inbound.has(path))
      findings.push({
        code: "orphan-page",
        path,
        line: 1,
        target: path,
        severity: "warning",
      });
  findings.sort(
    (a, b) =>
      a.path.localeCompare(b.path, "en") ||
      a.line - b.line ||
      a.code.localeCompare(b.code, "en"),
  );
  const counts = {};
  for (const f of findings) counts[f.code] = (counts[f.code] ?? 0) + 1;
  return {
    summary: {
      pages: documents.size,
      links: linkCount,
      errors: findings.filter((f) => f.severity === "error").length,
      counts,
    },
    findings,
  };
}
