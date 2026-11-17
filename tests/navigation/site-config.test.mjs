import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { existsSync, readFileSync } from "node:fs";
import { JSDOM } from "jsdom";
const source = readFileSync("Draft/index.html", "utf8");
const inline = [
  ...source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi),
].filter((m) => !m[0].includes(" src="));
test("website configuration evaluates without ReferenceError and retains sidebar/home/search together", () => {
  const context = { window: {} };
  vm.createContext(context);
  for (const script of inline) vm.runInContext(script[1], context);
  assert.equal(context.window.$docsify.loadSidebar, true);
  assert.equal(context.window.$docsify.homepage, "README.md");
  assert.equal(context.window.$docsify.search.paths, "auto");
  assert(context.window.$docsify.search.depth >= 3);
});
test("the configured favicon resolves to a checked-in local image", () => {
  const dom = new JSDOM(source);
  try {
    const href = dom.window.document
      .querySelector('link[rel="icon"]')
      .getAttribute("href");
    assert(
      existsSync(
        new URL(href, new URL("../../Draft/index.html", import.meta.url)),
      ),
    );
  } finally {
    dom.window.close();
  }
});
test("checked-in Docsify renderer preserves all managed ToC targets in rendered DOM", () => {
  const dom = new JSDOM('<!doctype html><body><div id="app"></div></body>', {
    url: "https://reference.test/docs/",
    runScripts: "outside-only",
  });
  try {
    // Disable application startup: this test exercises its actual compiler without making requests.
    const add = dom.window.document.addEventListener.bind(dom.window.document);
    dom.window.document.addEventListener = (name, ...rest) => {
      if (name !== "DOMContentLoaded") add(name, ...rest);
    };
    dom.window.eval(readFileSync("Draft/css/docsify4.js", "utf8"));
    for (const script of inline) dom.window.eval(script[1]);
    const manifest = JSON.parse(readFileSync("navigation/topics.json", "utf8"));
    for (const filename of manifest.tocPages) {
      const path = filename.slice(6, -3);
      const router = {
        getBasePath: () => "/docs/",
        getCurrentPath: () => "/" + path,
        parse: () => ({ file: path + ".md" }),
        toURL: (url, params) =>
          (url.startsWith("#") ? url : "#" + url) +
          (params ? "?" + new URLSearchParams(params) : ""),
      };
      const compiler = new dom.window.DocsifyCompiler(
        {
          noEmoji: true,
          relativePath: true,
          markdown: dom.window.$docsify.markdown,
        },
        router,
      );
      const source = readFileSync(filename, "utf8");
      const html = compiler.compile(source);
      const body = dom.window.document.createElement("div");
      body.innerHTML = html;
      assert(body.querySelector("h1"));
      const ids = new Set();
      for (const element of body.querySelectorAll("[id]")) {
        assert(
          !ids.has(element.id),
          `Duplicate rendered ID ${element.id} in ${path}`,
        );
        ids.add(element.id);
      }
      for (const heading of body.querySelectorAll("h1,h2,h3,h4"))
        assert(
          heading.querySelector("a.anchor")?.textContent.trim(),
          `Empty heading permalink in ${path}: ${heading.textContent}`,
        );
      if (path === "Embedded")
        for (const href of [
          "http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid",
          "https://www.youtube.com/watch?v=h-hohCfo4LA",
        ])
          assert(
            body.querySelector(`li a[href="${href}"]`),
            `Moved resource must remain clickable: ${href}`,
          );
      if (path === "Malware")
        assert.equal(
          body.querySelector("#pdf").closest("h3").textContent,
          "Portable Document Format(PDF)",
        );
      if (path === "Wireless") {
        const heading = body.querySelector("#ref-wireless-63").closest("h3");
        assert.equal(
          heading.textContent,
          "Articles/Presentations/Talks/Writeups",
        );
        assert(!heading.querySelector('a[href^="https:"]'));
        assert(
          body.querySelector(
            'li a[href="https://www.youtube.com/watch?v=F9kKo190_oE"]',
          ),
        );
      }
      if (path === "PrivEscPostExWin") {
        const alaris = [...body.querySelectorAll("a")].find(
          (link) =>
            link.href.includes("alaris") && link.textContent === "Blogpost",
        );
        assert(alaris, "Alaris blogpost must remain a clickable resource");
        assert(
          ![...body.querySelectorAll("pre")].some((block) =>
            block.textContent.includes("ScatterBrain is a shell code runner"),
          ),
        );
      }
      if (path === "Cloud")
        assert.equal(
          body.querySelector("#ref-cloud-26").closest("h3").textContent,
          "S3 Buckets",
        );
      const links = [...body.querySelectorAll("a")].filter((a) =>
        a.getAttribute("href")?.startsWith("#ref-"),
      );
      const toc = source.match(
        /<!-- nav:toc:start -->([\s\S]*?)<!-- nav:toc:end -->/,
      )[1];
      for (const [, fragment] of toc.matchAll(/\]\(#([^)]*)\)/g))
        assert(
          body.querySelector(`[id="${fragment}"]`) ||
            body.querySelector(`a[name="${fragment}"]`),
          `Missing managed ToC destination ${path}#${fragment}`,
        );
      if (path === "Exploit_Dev") {
        for (const [id, title] of [
          ["ref-exploit-27", "Windows Specific"],
          ["ref-exploit-shellcode-techniques", "Shellcode techniques"],
          ["ref-exploit-shellcode-reference", "Shellcode reference/resources"],
          ["ref-exploit-shellcode-repls", "Shellcode REPLs"],
          ["ref-exploit-shellcode-tools", "Shellcode tools"],
        ]) {
          assert.equal(
            body.querySelector(`[id="${id}"]`)?.closest("h4")?.textContent,
            title,
          );
          assert(links.some((link) => link.getAttribute("href") === "#" + id));
        }
      }
      for (const link of links)
        assert(
          body.querySelector(`[id="${link.getAttribute("href").slice(1)}"]`),
          `Missing rendered destination ${link.href}`,
        );
      if (path === "SE") {
        const probe = dom.window.document.createElement("div");
        probe.innerHTML = compiler.compile(
          '## <a id="ProbeCase"></a><a name="probe"> </a>Probe *format* & `code`',
        );
        const permalink = probe.querySelector("h2 a.anchor");
        assert.equal(permalink.textContent, "Probe format & code");
        assert.equal(permalink.querySelector("em").textContent, "format");
        assert.equal(permalink.querySelector("code").textContent, "code");
        assert(!probe.querySelector("#ProbeCase").closest("a.anchor"));
        assert(!probe.querySelector('a[name="probe"]').closest("a.anchor"));
      }
    }
  } finally {
    dom.window.close();
  }
});
