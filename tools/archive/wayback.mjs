import { lookup } from "node:dns/promises";
import { setTimeout as delay } from "node:timers/promises";
import { isPublicAddress } from "../navigation/external-links.mjs";

// Anonymous Save Page Now protocol used by Internet Archive's official extension.
const endpoint = "https://web.archive.org/save/";
const jobPattern = /^[a-zA-Z0-9-]{8,120}$/;
export async function saveWayback(
  originalUrl,
  {
    prior,
    fetchImpl = fetch,
    lookupHost = lookup,
    record = async () => {},
    sleep = delay,
  } = {},
) {
  const finish = async (data) => {
    const row = { originalUrl, checkedAt: new Date().toISOString(), ...data };
    await record(row);
    return row;
  };
  if (
    prior &&
    ["saved", "uncertain", "rejected", "failed"].includes(prior.state)
  )
    return prior;
  if (prior?.retryAt && Date.parse(prior.retryAt) > Date.now()) return prior;
  let url;
  try {
    url = new URL(originalUrl);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      !["", "80", "443"].includes(url.port)
    )
      throw Error("Unsafe public URL");
  } catch (error) {
    return finish({ state: "rejected", reason: error.message });
  }
  if (!prior?.jobId) {
    let addresses;
    try {
      addresses = await lookupHost(url.hostname.replace(/^\[|\]$/g, ""), {
        all: true,
      });
    } catch (error) {
      return finish({
        state: "deferred",
        reason: error.message,
        retryAt: new Date(Date.now() + 3600000).toISOString(),
      });
    }
    if (!addresses.length || addresses.some((a) => !isPublicAddress(a.address)))
      return finish({ state: "rejected", reason: "Non-public destination" });
  }
  let jobId = prior?.jobId;
  const request = async (path, options = {}) => {
    const response = await fetchImpl(endpoint + path, {
      ...options,
      redirect: "error",
      signal: AbortSignal.timeout(20000),
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml",
        ...options.headers,
      },
    });
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) throw Error("Wayback response exceeds 2 MiB");
      chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = {};
    }
    const retry = response.headers.get("retry-after");
    const retryMs = retry
      ? /^\d+$/.test(retry)
        ? Number(retry) * 1000
        : Date.parse(retry) - Date.now()
      : 6000;
    return {
      response,
      text,
      data,
      retryMs: Number.isFinite(retryMs) ? Math.max(6000, retryMs) : 6000,
    };
  };
  try {
    if (!jobId) {
      await finish({
        state: "uncertain",
        reason: "Submission started; no job ID recorded yet",
      });
      const reply = await request("", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          url: originalUrl,
          capture_outlinks: "0",
          capture_screenshot: "0",
        }).toString(),
      });
      if (reply.response.status === 429)
        return finish({
          state: "deferred",
          httpStatus: 429,
          retryAt: new Date(Date.now() + reply.retryMs).toISOString(),
        });
      if (!reply.response.ok)
        return finish({
          state: "uncertain",
          httpStatus: reply.response.status,
          reason: "Save request was not confirmed",
        });
      jobId = reply.data.job_id ?? reply.text.match(/\bspn2-[a-z0-9-]+\b/)?.[0];
      if (typeof jobId !== "string" || !jobPattern.test(jobId))
        return finish({
          state: "uncertain",
          reason: "No confirmed job ID; review before retrying",
        });
      await finish({ state: "pending", jobId });
    }
    if (!jobPattern.test(jobId))
      return finish({ state: "rejected", reason: "Invalid job ID" });
    for (let poll = 0; poll < 3; poll++) {
      const { response, data, retryMs } = await request("status/" + jobId, {
        method: "GET",
      });
      if (response.status === 429)
        return finish({
          state: "pending",
          jobId,
          retryAt: new Date(Date.now() + retryMs).toISOString(),
        });
      if (!response.ok) throw Error("Status request HTTP " + response.status);
      if (data.status === "success") {
        if (
          !/^\d{14}$/.test(data.timestamp) ||
          data.original_url?.split("#")[0] !== originalUrl.split("#")[0]
        )
          throw Error("Unconfirmed snapshot identity");
        return finish({
          state: "saved",
          jobId,
          timestamp: data.timestamp,
          archiveUrl:
            "https://web.archive.org/web/" + data.timestamp + "/" + originalUrl,
        });
      }
      if (data.status !== "pending")
        return finish({
          state: "failed",
          jobId,
          reason: "Save Page Now did not report success",
          status: data.status ?? "unknown",
        });
      if (poll === 2 || retryMs > 60000)
        return finish({
          state: "pending",
          jobId,
          retryAt: new Date(Date.now() + retryMs).toISOString(),
        });
      await sleep(retryMs);
    }
  } catch (error) {
    return finish({
      state: jobId ? "pending" : "uncertain",
      ...(jobId ? { jobId } : {}),
      reason: error.message,
    });
  }
}
