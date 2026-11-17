import { execFile, spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";
import { mkdir, writeFile, readFile, readdir, stat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { randomUUID, X509Certificate, createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const execute = promisify(execFile);
const root = resolve(import.meta.dirname, "../..");
const images = JSON.parse(
  await readFile(join(root, "navigation/archive-runtime.json"), "utf8"),
);
export const docker = async (...args) =>
  (
    await execute("docker", args, {
      maxBuffer: 4 * 1024 * 1024,
      timeout: 240000,
    })
  ).stdout.trim();
export function validatePolicy(policy) {
  if (policy.browserWorkers !== 1 || policy.perHostConcurrency !== 1)
    throw Error(
      "The bounded pilot currently supports one sequential browser navigation",
    );
  if (
    policy.publicNetworkOnly !== true ||
    policy.authenticatedCapture !== false ||
    policy.publishCaptures !== false ||
    policy.imageScope !== "article-only" ||
    policy.nonTextHandling !== "processing-queues" ||
    policy.format !== "warc.gz"
  )
    throw Error(
      "Capture requires the approved public, unauthenticated article-only WARC policy",
    );
  if (
    !Number.isInteger(policy.pageBudgetSeconds) ||
    policy.pageBudgetSeconds < 1 ||
    policy.pageBudgetSeconds > 120 ||
    !Number.isInteger(policy.pilotStorageCeilingBytes) ||
    policy.pilotStorageCeilingBytes < 1024 * 1024 ||
    policy.pilotStorageCeilingBytes > 1073741824
  )
    throw Error("Pilot exceeds supported time/storage bounds");
}
export async function filesBelow(path) {
  const files = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw Error("Symlink in capture output");
    const child = join(path, entry.name);
    if (entry.isDirectory()) files.push(...(await filesBelow(child)));
    else if (entry.isFile()) files.push(child);
  }
  return files;
}
export async function directoryBytes(path) {
  let size = 0;
  for (const file of await filesBelow(path)) size += (await stat(file)).size;
  return size;
}

export class BrowsertrixRuntime {
  constructor(directory, policy, runtimeImages = images) {
    this.directory = resolve(directory);
    this.policy = policy;
    this.images = runtimeImages;
    this.network = "infosec-archive-" + randomUUID();
    this.proxy = this.network + "-proxy";
    this.containers = new Set();
  }
  async start() {
    validatePolicy(this.policy);
    await mkdir(join(this.directory, "state"), {
      recursive: true,
      mode: 0o700,
    });
    this.runtimeIds = {
      browser: await docker(
        "image",
        "inspect",
        this.images.browserImage,
        "--format",
        "{{.Id}}",
      ),
      proxy: await docker(
        "image",
        "inspect",
        this.images.proxyImage,
        "--format",
        "{{.Id}}",
      ),
    };
    await docker("network", "create", "--internal", this.network);
    if (
      (await docker(
        "network",
        "inspect",
        this.network,
        "--format",
        "{{.Internal}}",
      )) !== "true"
    )
      throw Error("Capture network is not internal");
    await docker(
      "create",
      "--name",
      this.proxy,
      "--network",
      "bridge",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,size=64m",
      "-e",
      "PYTHONDONTWRITEBYTECODE=1",
      "-e",
      "PYTHONPATH=/tools",
      "-v",
      `${join(root, "tools/archive")}:/tools:ro`,
      "-v",
      `${join(this.directory, "state")}:/state`,
      "--entrypoint",
      "mitmdump",
      this.runtimeIds.proxy,
      "--quiet",
      "--listen-host",
      "0.0.0.0",
      "--listen-port",
      "8080",
      "--set",
      "confdir=/state",
      "--set",
      "connection_strategy=lazy",
      "--set",
      "upstream_cert=false",
      "--set",
      "http2=false",
      "-s",
      "/tools/proxy.py",
    );
    this.containers.add(this.proxy);
    await docker("network", "connect", this.network, this.proxy);
    await docker("start", this.proxy);
    for (let i = 0; i < 100; i++) {
      try {
        await readFile(join(this.directory, "state/ready"));
        const certificate = new X509Certificate(
          await readFile(join(this.directory, "state/mitmproxy-ca-cert.pem")),
        );
        this.spki = createHash("sha256")
          .update(certificate.publicKey.export({ type: "spki", format: "der" }))
          .digest("base64");
        const connected = JSON.parse(
          await docker(
            "inspect",
            this.proxy,
            "--format",
            "{{json .NetworkSettings.Networks}}",
          ),
        );
        this.proxyUrl = `http://${connected[this.network].IPAddress}:8080`;
        return;
      } catch {
        await delay(100);
      }
    }
    throw Error(
      "Archive proxy did not become ready: " +
        (await docker("logs", this.proxy)),
    );
  }
  async configure(documents, articleImages = []) {
    await writeFile(
      join(this.directory, "state/policy.json"),
      JSON.stringify({
        documents,
        images: articleImages,
        maxResponseBytes: 16 * 1024 * 1024,
        maxNetworkBytes: Math.floor(this.policy.pilotStorageCeilingBytes / 8),
      }),
    );
  }
  async run(stage, url) {
    const output = join(this.directory, stage);
    await mkdir(output);
    const remaining =
      this.policy.pilotStorageCeilingBytes -
      (await directoryBytes(this.directory));
    if (remaining < 1024 * 1024) throw Error("Pilot storage ceiling reached");
    const name = this.network + "-" + stage;
    const args =
      stage === "replay"
        ? [
            "qa",
            "--qaSource",
            "/source/collections/article/article.wacz",
            "--collection",
            "replay",
            "--text",
            "to-warc",
            "--generateWACZ",
          ]
        : [
            "crawl",
            "--url",
            url,
            "--collection",
            "article",
            "--scopeType",
            "page",
            "--limit",
            "1",
            "--driver",
            "/tools/driver.mjs",
            ...(stage === "discovery"
              ? ["--dryRun"]
              : ["--generateWACZ", "--generateCDX", "--text", "to-warc"]),
          ];
    args.push(
      "--workers",
      "1",
      "--headless",
      "--behaviors",
      "",
      "--pageLoadTimeout",
      String(this.policy.pageBudgetSeconds),
      "--timeLimit",
      String(this.policy.pageBudgetSeconds),
      "--maxPageRetries",
      "0",
      "--postLoadDelay",
      "1",
    );
    const mounts = [
      "-e",
      `ARCHIVE_STAGE=${stage}`,
      "-v",
      `${join(root, "tools/archive")}:/tools:ro`,
    ];
    if (stage === "replay")
      mounts.push("-v", `${join(this.directory, "capture")}:/source:ro`);
    else
      mounts.push(
        "-v",
        `${join(this.directory, "state/mitmproxy-ca-cert.pem")}:/state/mitmproxy-ca-cert.pem:ro`,
        "-e",
        "NODE_EXTRA_CA_CERTS=/state/mitmproxy-ca-cert.pem",
        "-e",
        `CHROME_FLAGS=--ignore-certificate-errors-spki-list=${this.spki} --proxy-bypass-list=<-loopback> --disable-quic`,
      );
    await docker(
      "create",
      "--name",
      name,
      "--network",
      stage === "replay" ? "none" : this.network,
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--memory",
      "4g",
      "--shm-size",
      "1g",
      "--tmpfs",
      `/crawls:rw,size=${remaining}`,
      ...mounts,
      "--entrypoint",
      "/bin/sh",
      this.runtimeIds.browser,
      "-c",
      '"$@"; result=$?; echo "$result" >/crawls/runtime-exit; sleep 300',
      "archive",
      ...args,
      ...(stage === "replay" ? [] : ["--proxyServer", this.proxyUrl]),
    );
    this.containers.add(name);
    try {
      await docker("start", name);
      const result = await execute(
        "docker",
        [
          "exec",
          name,
          "sh",
          "-c",
          "until [ -f /crawls/runtime-exit ]; do sleep 1; done; cat /crawls/runtime-exit",
        ],
        {
          timeout: (this.policy.pageBudgetSeconds + 60) * 1000,
          maxBuffer: 1024,
        },
      );
      // Docker cp omits tmpfs mounts; enumerate regular files and stream them explicitly.
      const paths = JSON.parse(
        await docker(
          "exec",
          name,
          "node",
          "-e",
          `const fs=require('fs');function walk(dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>{const p=dir+'/'+e.name;if(e.isSymbolicLink())throw Error('Symlink output');return e.isDirectory()?walk(p):e.isFile()?[p]:[]})}console.log(JSON.stringify(walk('/crawls')))`,
        ),
      );
      for (const path of paths) {
        if (path.includes("/profile/")) continue;
        if (!path.startsWith("/crawls/") || path.split("/").includes(".."))
          throw Error("Invalid container output path");
        const target = join(output, path.slice("/crawls/".length));
        await mkdir(resolve(target, ".."), { recursive: true });
        const child = spawn("docker", ["exec", name, "cat", path], {
          stdio: ["ignore", "pipe", "pipe"],
        });
        const done = new Promise((accept, reject) => {
          child.on("error", reject);
          child.on("exit", (code) =>
            code === 0 ? accept() : reject(Error("Output copy failed")),
          );
        });
        await Promise.all([
          pipeline(child.stdout, createWriteStream(target, { flags: "wx" })),
          done,
        ]);
      }
      await writeFile(join(output, "runtime.log"), await docker("logs", name));
      if (result.stdout.trim() !== "0")
        throw Error(
          `Browsertrix ${stage} exited ${result.stdout.trim()}; see ${output}/runtime.log`,
        );
      if (
        (await directoryBytes(this.directory)) >
        this.policy.pilotStorageCeilingBytes
      )
        throw Error("Pilot storage ceiling reached");
      return output;
    } finally {
      await docker("rm", "-f", name).catch(() => {});
      this.containers.delete(name);
    }
  }
  async verify(directory) {
    const result = await docker(
      "run",
      "--rm",
      "--network",
      "none",
      "--cap-drop",
      "ALL",
      "--read-only",
      "--entrypoint",
      "python3",
      "-v",
      `${join(root, "tools/archive")}:/tools:ro`,
      "-v",
      `${resolve(directory)}:/input:ro`,
      this.images.proxyImage,
      "-B",
      "/tools/verify.py",
      "/input",
    );
    return JSON.parse(result);
  }
  async close() {
    for (const name of this.containers)
      await docker("rm", "-f", name).catch(() => {});
    await docker("network", "rm", this.network).catch(() => {});
  }
}
