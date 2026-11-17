import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validatePolicy } from "../../tools/archive/runtime.mjs";
const policy = JSON.parse(
  readFileSync("navigation/archive-policy.json", "utf8"),
);
test("capture refuses disabled protections and unbounded time/storage", () => {
  assert.doesNotThrow(() => validatePolicy(policy));
  for (const change of [
    { publicNetworkOnly: false },
    { authenticatedCapture: true },
    { publishCaptures: true },
    { pilotStorageCeilingBytes: 0 },
    { pilotStorageCeilingBytes: 2 ** 31 },
    { pageBudgetSeconds: 121 },
    { imageScope: "all" },
    { nonTextHandling: "download" },
    { browserWorkers: 2 },
    { perHostConcurrency: 2 },
  ])
    assert.throws(() => validatePolicy({ ...policy, ...change }));
});
