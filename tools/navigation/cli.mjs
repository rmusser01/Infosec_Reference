import { resolve } from "node:path";
import { audit } from "./audit.mjs";
import { generate } from "./generate.mjs";
import { check } from "./check.mjs";
const args = process.argv.slice(2),
  command = args[0],
  rootIndex = args.indexOf("--root"),
  root = rootIndex >= 0 ? resolve(args[rootIndex + 1]) : process.cwd();
try {
  if (!["audit", "generate", "check"].includes(command))
    throw new Error(
      "Usage: node tools/navigation/cli.mjs <audit|generate|check> [--root path] [--format json]",
    );
  const result =
    command === "audit"
      ? audit(root)
      : command === "generate"
        ? generate(root)
        : check(root);
  console.log(JSON.stringify(result, null, 2));
  if (result.diagnostics?.length) process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
