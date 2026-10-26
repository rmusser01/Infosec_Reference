import test from "node:test";
import assert from "node:assert/strict";
import { compareBaseline } from "../../tools/navigation/check.mjs";
const error = {
  code: "missing-fragment",
  path: "Draft/old.md",
  line: 8,
  target: "#lost",
  severity: "error",
};
const entry = {
  code: "missing-fragment",
  path: "Draft/old.md",
  target: "#lost",
  reason: "Legacy document awaiting migration",
};
test("baseline allows unchanged debt but rejects new failures and stale exemptions", () => {
  assert.equal(compareBaseline([error], [entry], []).length, 0);
  assert(
    compareBaseline([{ ...error, target: "#new" }], [entry], []).some(
      (d) => d.code === "new-navigation-error",
    ),
  );
  assert(
    compareBaseline([], [entry], []).some(
      (d) => d.code === "stale-baseline-entry",
    ),
  );
  assert(
    compareBaseline([error], [entry], ["Draft/old.md"]).some(
      (d) => d.code === "managed-baseline-exemption",
    ),
  );
  assert(compareBaseline([{ ...error, line: 99 }], [entry], []).length === 0);
});
test("baseline counts reject copied defects and require partial repairs to shrink exemptions", () => {
  const copied = { ...error, line: 30 };
  assert(
    compareBaseline([error, copied], [entry], []).some(
      (d) => d.code === "new-navigation-error",
    ),
  );
  assert.equal(
    compareBaseline([error, copied], [{ ...entry, occurrences: 2 }], []).length,
    0,
  );
  assert(
    compareBaseline([error], [{ ...entry, occurrences: 2 }], []).some(
      (d) => d.code === "stale-baseline-entry",
    ),
  );
});
