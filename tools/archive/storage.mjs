import { createReadStream } from "node:fs";
import { lstat, mkdir, copyFile, chmod, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { basename, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function describeObject(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw Error("Archive object must be a regular file");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return {
    uri: pathToFileURL(resolve(path)).href,
    bytes: stat.size,
    sha256: hash.digest("hex"),
  };
}

export async function verifyObjects(objects) {
  if (!objects?.length) throw Error("No archive objects");
  for (const object of objects) {
    const actual = await describeObject(fileURLToPath(object.uri));
    if (
      actual.bytes <= 0 ||
      actual.bytes !== object.bytes ||
      actual.sha256 !== object.sha256
    )
      throw Error("Archive object length/checksum mismatch");
  }
  return true;
}

export async function persistCapture(
  attempt,
  { primary, backup, durable = false },
) {
  if (
    !/^[a-zA-Z0-9-]+$/.test(attempt.captureId) ||
    !primary ||
    !backup ||
    resolve(primary) === resolve(backup)
  )
    throw Error("Choose distinct primary and backup archive directories");
  await verifyObjects(attempt.objects);
  const roots = [];
  for (const destination of [primary, backup]) {
    await mkdir(destination, { recursive: true });
    roots.push(await realpath(destination));
  }
  if (roots[0] === roots[1])
    throw Error("Primary and backup resolve to the same directory");
  if (durable && (await lstat(roots[0])).dev === (await lstat(roots[1])).dev)
    throw Error(
      "Durable storage requires explicitly configured independent mounted filesystems",
    );
  const objects = [];
  for (const [index, root] of roots.entries()) {
    const directory = join(root, attempt.captureId);
    await mkdir(directory);
    for (const [i, object] of attempt.objects.entries()) {
      const name =
        object.relativePath ?? `${i}-${basename(fileURLToPath(object.uri))}`;
      if (
        name.startsWith("/") ||
        name.includes("\\") ||
        name.includes(":") ||
        name.split("/").some((p) => !p || p === "." || p === "..")
      )
        throw Error("Invalid archive object relative path");
      const target = join(directory, name);
      await mkdir(resolve(target, ".."), { recursive: true });
      await copyFile(
        fileURLToPath(object.uri),
        target,
        constants.COPYFILE_EXCL,
      );
      await chmod(target, 0o444);
      const copied = {
        ...object,
        uri: pathToFileURL(target).href,
        copy: index === 0 ? "primary" : "backup",
      };
      await verifyObjects([copied]);
      objects.push(copied);
    }
  }
  return {
    ...attempt,
    copyState: "verified",
    storageState: durable ? "verified" : "copied",
    objects,
  };
}
