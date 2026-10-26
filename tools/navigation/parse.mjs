import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import GithubSlugger from "github-slugger";
import { toString } from "mdast-util-to-string";
import { parseFragment } from "parse5";

const parser = unified().use(remarkParse).use(remarkGfm);
export function parseDocument(source, path) {
  const tree = parser.parse(source),
    slugger = new GithubSlugger();
  const result = { path, headings: [], anchors: [], links: [], issues: [] };
  const definitions = new Map();
  const walk = (node, fn) => {
    fn(node);
    for (const child of node.children ?? node.childNodes ?? []) walk(child, fn);
  };
  walk(tree, (n) => {
    if (n.type === "definition" && !definitions.has(n.identifier.toLowerCase()))
      definitions.set(n.identifier.toLowerCase(), n);
  });
  const addAnchor = (fragment, line, explicit) =>
    result.anchors.push({ fragment, line, explicit });
  walk(tree, (node) => {
    const line = node.position?.start.line ?? 1;
    if (node.type === "heading") {
      const text = toString(node, { includeHtml: false }).trim();
      const fragment = slugger.slug(text);
      result.headings.push({
        text,
        fragment,
        depth: node.depth,
        line,
        endLine: node.position.end.line,
      });
      addAnchor(fragment, line, false);
    }
    if (
      ["link", "image", "linkReference", "imageReference"].includes(node.type)
    ) {
      const ref = ["link", "image"].includes(node.type)
        ? node
        : definitions.get(node.identifier?.toLowerCase());
      if (ref?.url === "" && !node.type.startsWith("image"))
        result.issues.push({
          code: "empty-link-destination",
          path,
          line,
          target: toString(node, { includeHtml: false }),
          severity: "error",
        });
      if (ref)
        result.links.push({
          url: ref.url,
          label: toString(node, { includeHtml: false }),
          kind: node.type.startsWith("image") ? "image" : "link",
          line,
        });
    }
    if (node.type === "html") {
      const fragment = parseFragment(node.value, {
        sourceCodeLocationInfo: true,
      });
      walk(fragment, (n) => {
        const attrs = Object.fromEntries(
          (n.attrs ?? []).map((a) => [a.name, a.value]),
        );
        const offset = (n.sourceCodeLocation?.startLine ?? 1) - 1;
        if (attrs.id) addAnchor(attrs.id, line + offset, true);
        if (n.tagName === "a" && attrs.name && attrs.name !== attrs.id)
          addAnchor(attrs.name, line + offset, true);
        if (n.tagName === "a" && attrs.href === "")
          result.issues.push({
            code: "empty-link-destination",
            path,
            line: line + offset,
            target: node.value.trim(),
            severity: "error",
          });
        if (n.tagName === "a" && attrs.href)
          result.links.push({
            url: attrs.href,
            label: "",
            kind: "link",
            line: line + offset,
          });
        if (n.tagName === "img" && attrs.src)
          result.links.push({
            url: attrs.src,
            label: attrs.alt ?? "",
            kind: "image",
            line: line + offset,
          });
      });
      if (/<a\b[^>]*$/i.test(node.value))
        result.issues.push({
          code: "malformed-anchor",
          path,
          line,
          target: node.value.trim(),
          severity: "warning",
        });
    }
  });
  // An explicit alias on the same heading is one destination, not a collision.
  result.anchors = result.anchors.filter(
    (a, i, all) =>
      all.findIndex((b) => b.fragment === a.fragment && b.line === a.line) ===
      i,
  );
  return result;
}
