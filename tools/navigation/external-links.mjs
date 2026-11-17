import ipaddr from "ipaddr.js";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyResource } from "./resources.mjs";
export function isPublicAddress(address) {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}
async function destination(url, resolveHost, timeoutMs) {
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw Object.assign(
      new Error("Unsupported scheme or embedded credentials"),
      { blocked: true },
    );
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(hostname)
    ? [{ address: hostname, family: isIP(hostname) }]
    : await timed(
        resolveHost(hostname, { all: true, verbatim: true }),
        timeoutMs,
      );
  if (!addresses.length || addresses.some((a) => !isPublicAddress(a.address)))
    throw Object.assign(new Error("Non-public destination"), { blocked: true });
  return addresses;
}
async function timed(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Timeout")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function request(url, { method, addresses, timeoutMs }) {
  return new Promise((resolveRequest, reject) => {
    const client = url.protocol === "https:" ? https : http;
    const req = client.request(
      url,
      {
        method,
        agent: false,
        headers: {
          "User-Agent": "Infosec-Reference-Link-Validator/1.0",
          ...(method === "GET" ? { Range: "bytes=0-4095" } : {}),
        },
        lookup: (host, options, cb) =>
          options.all
            ? cb(null, addresses)
            : cb(null, addresses[0].address, addresses[0].family),
      },
      (response) => {
        // Headers suffice for validation; never stream arbitrary bodies into memory.
        const result = {
          status: response.statusCode,
          headers: response.headers,
        };
        response.destroy();
        resolveRequest(result);
      },
    );
    const timer = setTimeout(
      () => req.destroy(new Error("Timeout")),
      timeoutMs,
    );
    req.on("error", reject);
    req.on("close", () => clearTimeout(timer));
    req.end();
  });
}
export async function inspectUrl(
  originalUrl,
  { resolveHost = lookup, request: send = request, timeoutMs = 15000 } = {},
) {
  const result = {
    originalUrl,
    checkedAt: new Date().toISOString(),
    redirectChain: [],
    availabilityState: "uncertain",
  };
  try {
    let url = new URL(originalUrl);
    url.hash = "";
    let redirects = 0;
    for (;;) {
      const addresses = await destination(url, resolveHost, timeoutMs);
      let response;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          response = await timed(
            send(url, { method: "HEAD", addresses, timeoutMs }),
            timeoutMs,
          );
          if ([405, 501].includes(response.status))
            response = await timed(
              send(url, { method: "GET", addresses, timeoutMs }),
              timeoutMs,
            );
          if (response.status !== 429 && response.status < 500) break;
        } catch (error) {
          if (attempt === 1) throw error;
        }
      }
      result.finalUrl = url.href;
      result.httpStatus = response.status;
      result.contentType = response.headers["content-type"] ?? null;
      if (
        [301, 302, 303, 307, 308].includes(response.status) &&
        response.headers.location
      ) {
        if (redirects++ >= 5) throw new Error("Redirect limit exceeded");
        const next = new URL(response.headers.location, url);
        result.redirectChain.push({
          from: url.href,
          to: next.href,
          status: response.status,
        });
        url = next;
        continue;
      }
      result.availabilityState =
        response.status >= 200 && response.status < 300
          ? "reachable"
          : [404, 410].includes(response.status)
            ? "missing"
            : "uncertain";
      result.classification = classifyResource(
        { url: originalUrl },
        {
          finalUrl: result.finalUrl,
          contentType: result.contentType,
          httpStatus: result.httpStatus,
          availabilityState: result.availabilityState,
        },
      );
      return result;
    }
  } catch (error) {
    result.availabilityState = error.blocked ? "blocked" : "uncertain";
    result.error = error.message;
    return result;
  }
}
export async function checkExternal(urls, options = {}) {
  const results = new Array(urls.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(4, urls.length) }, async () => {
      while (next < urls.length) {
        const i = next++;
        results[i] = await inspectUrl(urls[i], options);
      }
    }),
  );
  return results;
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
  const limit = Number(value("--limit", "100")),
    offset = Number(value("--offset", "0"));
  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 1000 ||
    !Number.isSafeInteger(offset) ||
    offset < 0
  )
    throw Error("Use --limit 1..1000 and nonnegative --offset");
  const rows = readFileSync("docs/inventories/resource-inventory.jsonl", "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
  const urls = rows.slice(offset, offset + limit).map((r) => r.url),
    results = await checkExternal(urls);
  const report = {
    offset,
    limit,
    totalInventory: rows.length,
    checked: results.length,
    results,
  };
  writeFileSync(
    value("--output", "external-report.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(
    JSON.stringify({
      offset,
      checked: results.length,
      totalInventory: rows.length,
    }),
  );
}
