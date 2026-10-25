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
      if (path === "Cloud")
        assert.equal(
          body.querySelector("#ref-cloud-26").closest("h3").textContent,
          "S3 Buckets",
        );
      const links = [...body.querySelectorAll("a")].filter((a) =>
        a.getAttribute("href")?.startsWith("#ref-"),
      );
      assert(links.length > 3, `No generated ToC links rendered for ${path}`);
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
