import { lstatSync, realpathSync } from "node:fs";
import { resolve, relative, join, sep } from "node:path";
// Fixed repository inputs/outputs must not follow links into unrelated content.
export function repositoryPath(
  root,
  path,
  { allowMissing = false, kind = "file" } = {},
) {
  const base = resolve(root),
    full = resolve(base, path),
    parts = relative(base, full).split(sep).filter(Boolean);
  const unsafe = (reason) =>
    Object.assign(new Error("Unsafe repository path " + path + ": " + reason), {
      code: "UNSAFE_PATH",
    });
  if (parts[0] === "..") throw unsafe("outside repository");
  const realRoot = realpathSync(base);
  let current = base;
  for (let i = 0; i < parts.length; i++) {
    current = join(current, parts[i]);
    let stat;
    try {
      stat = lstatSync(current);
    } catch (error) {
      if (error.code === "ENOENT" && allowMissing) return full;
      throw error;
    }
    if (stat.isSymbolicLink()) throw unsafe("symlink is not supported");
    const real = realpathSync(current),
      inside = relative(realRoot, real);
    if (inside === ".." || inside.startsWith(".." + sep))
      throw unsafe("outside repository");
    if (i < parts.length - 1 && !stat.isDirectory())
      throw unsafe("non-directory ancestor");
    if (
      i === parts.length - 1 &&
      ((kind === "file" && !stat.isFile()) ||
        (kind === "directory" && !stat.isDirectory()))
    )
      throw unsafe("non-regular " + kind);
  }
  return full;
}
