import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
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
test("checked-in Docsify renderer preserves pilot ToC targets in rendered DOM", () => {
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
    for (const path of [
      "Active_Directory",
      "DFIR",
      "L-SM-TH",
      "Cloud",
      "Containers",
      "Basic",
      "Building_A_Lab",
      "Career",
      "Courses_Training",
      "Docs_and_Reports",
      "threatmodel",
      "Osint",
      "Exfiltration",
      "Fuzzing",
      "Exploit_Dev",
      "RE",
      "Programming_Language_Security",
      "Defense",
      "Web",
      "RT",
      "PrivEscPostExWin",
      "PrivescPostExLin",
      "PrivescPostExmac",
      "PrivescPostEx",
      "sysinternals",
      "Network_Attacks",
      "Physical_Security",
      "Phishing",
      "Wireless",
    ]) {
      const router = {
        getBasePath: () => "/docs/",
        getCurrentPath: () => "/" + path,
        parse: () => ({ file: path + ".md" }),
        toURL: (url, params) =>
          (url.startsWith("#") ? url : "#" + url) +
          (params ? "?" + new URLSearchParams(params) : ""),
      };
      const compiler = new dom.window.DocsifyCompiler(
        { noEmoji: true, relativePath: true },
        router,
      );
      const html = compiler.compile(
        readFileSync("Draft/" + path + ".md", "utf8"),
      );
      const body = dom.window.document.createElement("div");
      body.innerHTML = html;
      assert(body.querySelector("h1"));
      if (path === "Wireless") {
        const heading = body.querySelector("#ref-wireless-63").closest("h3");
        assert.equal(heading.textContent, "Articles/Presentations/Talks/Writeups");
        assert(!heading.querySelector('a[href^="https:"]'));
        assert(body.querySelector('li a[href="https://www.youtube.com/watch?v=F9kKo190_oE"]'));
      }
      if (path === "PrivEscPostExWin") {
        const alaris = [...body.querySelectorAll("a")].find((link) =>
          link.href.includes("alaris") && link.textContent === "Blogpost",
        );
        assert(alaris, "Alaris blogpost must remain a clickable resource");
        assert(![...body.querySelectorAll("pre")].some((block) =>
          block.textContent.includes("ScatterBrain is a shell code runner"),
        ));
      }
      if (path === "Cloud")
        assert.equal(
          body.querySelector("#ref-cloud-26").closest("h3").textContent,
          "S3 Buckets",
        );
      const links = [...body.querySelectorAll("a")].filter((a) =>
        a.getAttribute("href")?.startsWith("#ref-"),
      );
      assert(links.length > 3, `No generated ToC links rendered for ${path}`);
      if (path === "Exploit_Dev") {
        for (const [id, title] of [
          ["ref-exploit-27", "Windows Specific"],
          ["ref-exploit-shellcode-techniques", "Shellcode techniques"],
          ["ref-exploit-shellcode-reference", "Shellcode reference/resources"],
          ["ref-exploit-shellcode-repls", "Shellcode REPLs"],
          ["ref-exploit-shellcode-tools", "Shellcode tools"],
        ]) {
          assert.equal(body.querySelector(`[id="${id}"]`)?.closest("h4")?.textContent, title);
          assert(links.some((link) => link.getAttribute("href") === "#" + id));
        }
      }
      for (const link of links)
        assert(
          body.querySelector(`[id="${link.getAttribute("href").slice(1)}"]`),
          `Missing rendered destination ${link.href}`,
        );
    }
  } finally {
    dom.window.close();
  }
});
