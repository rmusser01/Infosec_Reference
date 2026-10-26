import test from "node:test";
import { execFileSync } from "node:child_process";
test("archive proxy policy blocks private DNS, unrelated images, media and non-text response bodies", () => {
  execFileSync("python3", ["-B", "tests/archive/policy_test.py"], {
    stdio: "pipe",
  });
});
