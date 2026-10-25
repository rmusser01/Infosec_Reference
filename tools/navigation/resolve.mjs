import { resolve, relative, dirname, sep } from "node:path";
import {
  existsSync,
  statSync,
  readFileSync,
  realpathSync,
  readdirSync,
} from "node:fs";
import { parseDocument } from "./parse.mjs";
const repo =
  /^https?:\/\/(?:www\.)?github\.com\/rmusser01\/Infosec_Reference\/(?:blob|tree)\/(?:master|main)\//i;
export function resolveInternalLink(
  root,
  sourcePath,
  destination,
  documents = new Map(),
) {
  try {
    let target = destination;
    if (repo.test(target)) target = "/" + target.replace(repo, "");
    else if (/^[a-z][a-z\d+.-]*:/i.test(target))
      return { kind: /^https?:/i.test(target) ? "external" : "ignored" };
    if (target.startsWith("//")) return { kind: "external" };
    const hash = target.indexOf("#");
    const fragment =
      hash >= 0 ? decodeURIComponent(target.slice(hash + 1)) : "";
    const pathPart = decodeURIComponent(
      (hash >= 0 ? target.slice(0, hash) : target).split("?")[0],
    );
    const full = pathPart
      ? resolve(
          root,
          pathPart.startsWith("/") ? "." + pathPart : dirname(sourcePath),
          pathPart.startsWith("/") ? "" : pathPart,
        )
      : resolve(root, sourcePath);
    const path = relative(resolve(root), full).split(sep).join("/");
    const error = (code) => ({ kind: "error", code, path, fragment });
    if (path === ".." || path.startsWith("../")) return error("outside-root");
    if (!existsSync(full)) return error("missing-file");
    let parent = resolve(root);
    for (const part of path.split("/").filter(Boolean)) {
      if (!readdirSync(parent).includes(part)) return error("missing-file");
      parent = resolve(parent, part);
    }
    if (
      !realpathSync(full).startsWith(realpathSync(root) + sep) &&
      realpathSync(full) !== realpathSync(root)
    )
      return error("outside-root");
    if (statSync(full).isDirectory())
      return { kind: "directory", path, fragment };
    if (fragment && /\.md$/i.test(path)) {
      let doc = documents.get(path);
      if (!doc) {
        doc = parseDocument(readFileSync(full, "utf8"), path);
        documents.set(path, doc);
      }
      if (!doc.anchors.some((a) => a.fragment === fragment))
        return error("missing-fragment");
    }
    return { kind: "internal", path, fragment };
  } catch {
    return {
      kind: "error",
      code: "invalid-url",
      path: sourcePath,
      fragment: "",
    };
  }
}
