import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { readArticle } from "../../tools/archive/article.mjs";

test("article scope includes inline figures, excludes navigation/ads/media, and retains embed queues", () => {
  const dom = new JSDOM(
    `<title>A useful article</title><nav><img src="/logo.png"></nav>
    <main><article><h1>A useful article</h1><p>${"Detailed article text. ".repeat(15)}</p>
    <figure><img src="/figure.png"><figcaption>Diagram</figcaption></figure>
    <svg><image href="/svg-figure.png"></image></svg>
    <figure style="background-image:url('/background-figure.png')"></figure>
    <aside><img src="/advert.png"></aside><div class="advertisement"><img src="/ad.png"></div>
    <img src="/pixel.gif" width="1" height="1">
    <video src="/clip.mp4"></video><iframe src="https://video.example/watch/1"></iframe>
    <a href="/paper.pdf">Paper</a></article></main>`,
    { url: "https://example.org/post?q=1" },
  );
  try {
    const result = readArticle(dom.window.document);
    assert.equal(result.state, "article");
    assert.deepEqual(result.images, [
      "https://example.org/figure.png",
      "https://example.org/svg-figure.png",
      "https://example.org/background-figure.png",
    ]);
    assert(result.text.includes("Detailed article text."));
    assert.deepEqual(
      result.embeds.map((e) => e.url),
      ["https://example.org/clip.mp4", "https://video.example/watch/1"],
    );
    assert(result.links.includes("https://example.org/paper.pdf"));
  } finally {
    dom.window.close();
  }
});

test("HTTP-200 challenge/login pages and ambiguous body-only layouts cannot become complete articles", () => {
  for (const [html, state] of [
    [
      "<title>Just a moment...</title><main><p>Verify you are human</p></main>",
      "access-wall",
    ],
    ['<main><form><input type="password"></form></main>', "access-wall"],
    [
      `<title>Service unavailable</title><main><h1>Too many requests</h1><p>${"Please retry later or contact support. ".repeat(8)}</p></main>`,
      "access-wall",
    ],
    [
      `<title>Article</title><main><h1>Page not found</h1><p>${"The requested content is not available. ".repeat(8)}</p></main>`,
      "access-wall",
    ],
    [`<h1>Blog</h1><p>${"Text ".repeat(60)}</p>`, "needs-review"],
  ]) {
    const dom = new JSDOM(html, { url: "https://example.org/" });
    try {
      assert.equal(readArticle(dom.window.document).state, state);
    } finally {
      dom.window.close();
    }
  }
});

test("explicit articleBody microdata identifies legacy Blogger text and figures without sidebar images", () => {
  const dom = new JSDOM(
    `<title>Legacy Blogger post</title><aside><img src="/profile.png"></aside>
    <div class="post-body entry-content" itemprop="description articleBody"><p>${"Specific article text. ".repeat(12)}</p>
    <img src="/figure.png" loading="lazy"><div class="ads"><img src="/advert.png"></div></div>
    <div class="post-footer">Share and subscribe</div>`,
    { url: "https://example.blogspot.com/2015/post.html" },
  );
  try {
    const article = readArticle(dom.window.document);
    assert.equal(article.state, "article");
    assert(article.text.startsWith("Specific article text."));
    assert(!article.text.includes("Share and subscribe"));
    assert.deepEqual(article.images, [
      "https://example.blogspot.com/figure.png",
    ]);
  } finally {
    dom.window.close();
  }
  const ambiguous = new JSDOM(
    `<div itemprop="articleBody">${"One post ".repeat(25)}</div><div itemprop="articleBody">${"Other post ".repeat(25)}</div>`,
  );
  try {
    assert.equal(readArticle(ambiguous.window.document).state, "needs-review");
  } finally {
    ambiguous.window.close();
  }
});
