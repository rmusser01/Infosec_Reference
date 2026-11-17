import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { repositoryPath } from "./paths.mjs";
import { audit } from "./audit.mjs";
import { generate } from "./generate.mjs";
const key = (f) => JSON.stringify([f.path, f.code, f.target]);
export function compareBaseline(findings, baseline, managedPaths) {
  const errors = findings.filter((f) => f.severity === "error"),
    actual = new Map(),
    known = new Map(),
    diagnostics = [];
  for (const error of errors)
    actual.set(key(error), (actual.get(key(error)) ?? 0) + 1);
  for (const entry of baseline) {
    const count = entry.occurrences ?? 1;
    if (!Number.isSafeInteger(count) || count < 1 || known.has(key(entry)))
      diagnostics.push({ ...entry, code: "invalid-baseline-entry" });
    known.set(key(entry), count);
    if (!entry.reason || (actual.get(key(entry)) ?? 0) < count)
      diagnostics.push({ ...entry, code: "stale-baseline-entry" });
    if (managedPaths.includes(entry.path))
      diagnostics.push({ ...entry, code: "managed-baseline-exemption" });
  }
  const seen = new Map();
  for (const error of errors) {
    const count = (seen.get(key(error)) ?? 0) + 1;
    seen.set(key(error), count);
    if (count > (known.get(key(error)) ?? 0))
      diagnostics.push({
        ...error,
        code: "new-navigation-error",
        originalCode: error.code,
      });
  }
  return diagnostics;
}
export function check(root) {
  const generated = generate(root, { check: true });
  if (generated.diagnostics.length)
    return { ...generated, diagnostics: generated.diagnostics };
  const report = audit(root),
    path = join(root, "navigation/legacy-errors.json");
  const baseline = existsSync(path)
    ? JSON.parse(
        readFileSync(
          repositoryPath(root, "navigation/legacy-errors.json"),
          "utf8",
        ),
      )
    : [];
  const m = JSON.parse(
    readFileSync(repositoryPath(root, "navigation/topics.json"), "utf8"),
  );
  const managed = [
    "README.md",
    "Draft/README.md",
    "Draft/_sidebar.md",
    "Draft/Subject_Index.md",
    ...m.tocPages,
  ];
  const diagnostics = [
    ...compareBaseline(report.findings, baseline, managed),
    ...generated.changedPaths.map((path) => ({
      code: "stale-generated-output",
      path,
    })),
  ];
  return {
    summary: report.summary,
    changedPaths: generated.changedPaths,
    diagnostics,
  };
}
