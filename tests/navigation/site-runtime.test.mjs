import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, extname } from "node:path";
import { JSDOM, VirtualConsole } from "jsdom";
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(check, timeout = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (check()) return;
    await pause(30);
  }
  assert.fail("Timed out waiting for rendered website");
}
test(
  "Docsify boots under /docs, renders deep routes and searches pilot content",
  { timeout: 60000 },
  async () => {
    const root = resolve("Draft"),
      requests = [];
    const server = createServer((req, res) => {
      try {
        const route = decodeURIComponent(
          new URL(req.url, "http://localhost").pathname,
        );
        requests.push(route);
        if (!route.startsWith("/docs/")) {
          res.writeHead(404).end();
          return;
        }
        let path = resolve(root, "." + route.slice(5));
        if (!path.startsWith(root + "/") && path !== root) {
          res.writeHead(403).end();
          return;
        }
        if (existsSync(path) && statSync(path).isDirectory())
          path += "/index.html";
        const mime =
          {
            ".js": "text/javascript",
            ".css": "text/css",
            ".html": "text/html",
            ".md": "text/plain",
          }[extname(path)] ?? "application/octet-stream";
        let bytes = readFileSync(path);
        if (route === "/docs/DFIR.md")
          bytes =
            bytes.toString() +
            '\n\n## <a id="OldCase"></a> Case-sensitive Anchor Probe\n\nCaseSensitiveAnchorProbe\n';
        res.writeHead(200, { "Content-Type": mime });
        res.end(bytes);
      } catch {
        res.writeHead(404).end();
      }
    });
    await new Promise((r, j) => {
      server.once("error", j);
      server.listen(0, "127.0.0.1", r);
    });
    const errors = [],
      console = new VirtualConsole();
    console.on("jsdomError", (e) => errors.push(e.message));
    let dom;
    try {
      const url = `http://127.0.0.1:${server.address().port}/docs/#/Active_Directory?id=ref-ad-1`;
      dom = await JSDOM.fromURL(url, {
        resources: "usable",
        runScripts: "dangerously",
        pretendToBeVisual: true,
        virtualConsole: console,
        beforeParse: (w) => {
          w.scrollTo = () => {};
        },
      });
      await until(() =>
        dom.window.document.querySelector(".markdown-section #ref-ad-1"),
      );
      await until(() =>
        dom.window.document.querySelector('.sidebar-nav a[href*="DFIR"]'),
      );
      const toc = dom.window.document.querySelector(
        '.markdown-section a[href*="id=ref-ad-3"]',
      );
      assert(toc, "ToC route fragment missing");
      assert.equal(new URL(toc.href).hash, "#/Active_Directory?id=ref-ad-3");
      await until(() => dom.window.document.querySelector(".search input"));
      await until(
        () =>
          requests.some((p) => p === "/docs/DFIR.md") &&
          requests.some((p) => p === "/docs/L-SM-TH.md"),
      );
      const input = dom.window.document.querySelector(".search input");
      for (const [query, target] of [
        ["Kerberoasting", "Active_Directory"],
        ["Introduction to DFIR", "DFIR"],
        ["Funnel of Fidelity", "L-SM-TH"],
        ["CaseSensitiveAnchorProbe", "DFIR"],
      ]) {
        input.value = query;
        input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
        try {
          await until(() =>
            [...dom.window.document.querySelectorAll(".matching-post a")].some(
              (a) =>
                a.href.includes(target) &&
                a
                  .closest(".matching-post")
                  .textContent.toLowerCase()
                  .includes(query.toLowerCase()),
            ),
          );
        } catch (error) {
          assert.fail(
            query +
              " errors=" +
              JSON.stringify(errors) +
              " connected=" +
              input.isConnected +
              " value=" +
              input.value +
              " actual=" +
              dom.window.document.querySelector(".search input").value +
              " results: " +
              JSON.stringify(
                [...dom.window.document.querySelectorAll(".matching-post")]
                  .slice(0, 4)
                  .map((a) => ({
                    text: a.textContent.slice(0, 300),
                    html: a.innerHTML.slice(0, 300),
                  })),
              ),
          );
        }
      }
      input.value = "CaseSensitiveAnchorProbe";
      input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      await until(() =>
        [...dom.window.document.querySelectorAll(".matching-post a")].some(
          (a) =>
            a.href.includes("DFIR") &&
            a.textContent.includes("CaseSensitiveAnchorProbe"),
        ),
      );
      const caseResult = [
        ...dom.window.document.querySelectorAll(".matching-post a"),
      ].find(
        (a) =>
          a.href.includes("DFIR") &&
          a.textContent.includes("CaseSensitiveAnchorProbe"),
      );
      assert.equal(new URL(caseResult.href).hash, "#/DFIR?id=OldCase");
      dom.window.location.hash = new URL(caseResult.href).hash;
      await until(() =>
        dom.window.document.querySelector(".markdown-section #OldCase"),
      );
      dom.window.location.hash = "#/DFIR";
      await until(() =>
        dom.window.document.querySelector(".markdown-section #ref-dfir-1"),
      );
      assert(
        !errors.some((e) =>
          /ReferenceError|QuotaExceeded|SyntaxError|TypeError/.test(e),
        ),
        errors.join("\n"),
      );
    } finally {
      dom?.window.close();
      await new Promise((r) => server.close(r));
    }
  },
);
