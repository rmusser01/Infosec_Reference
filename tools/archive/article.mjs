// This function also runs inside the isolated crawler's page.
export function readArticle(document = globalThis.document) {
  const title = document.title;
  if (
    /just a moment|access denied|verify.{0,20}human|captcha|sign in|log in/i.test(
      title,
    ) ||
    document.querySelector(
      'input[type="password"],#challenge-form,.g-recaptcha',
    )
  )
    return {
      state: "access-wall",
      title,
      images: [],
      embeds: [],
      links: [],
      text: "",
    };
  const bodies = document.querySelectorAll('[itemprop~="articleBody"]');
  const root =
    document.querySelector("article") ??
    (bodies.length === 1 ? bodies[0] : null) ??
    document.querySelector('main,[role="main"]');
  if (!root)
    return {
      state: "needs-review",
      title,
      images: [],
      embeds: [],
      links: [],
      text: "",
    };
  const errorSignals =
    title +
    " " +
    (root.querySelector("h1")?.textContent ?? "") +
    " " +
    root.textContent.slice(0, 300);
  if (
    /service unavailable|too many requests|rate limit|page not found|404 not found|403 forbidden|temporarily unavailable|you have been blocked|checking your browser|verify (?:that )?you are human/i.test(
      errorSignals,
    )
  )
    return {
      state: "access-wall",
      title,
      images: [],
      embeds: [],
      links: [],
      text: "",
    };
  const excluded =
    'aside,nav,footer,[role="navigation"],.advertisement,.ads,[data-ad],video,audio,iframe,object,embed';
  const url = (value) => {
    try {
      const u = new URL(value, document.baseURI);
      u.hash = "";
      return ["http:", "https:"].includes(u.protocol) ? u.href : null;
    } catch {
      return null;
    }
  };
  const images = [...root.querySelectorAll("img")]
    .filter(
      (el) =>
        !el.closest(excluded) &&
        !(
          el.getAttribute("width") === "1" && el.getAttribute("height") === "1"
        ),
    )
    .map((el) =>
      [el.currentSrc, el.getAttribute("data-src"), el.getAttribute("src")]
        .filter(Boolean)
        .map(url)
        .find(Boolean),
    )
    .filter(Boolean);
  for (const image of root.querySelectorAll("svg image")) {
    if (!image.closest(excluded))
      images.push(
        url(image.getAttribute("href") ?? image.getAttribute("xlink:href")),
      );
  }
  for (const figure of root.querySelectorAll('figure,[role="img"]')) {
    if (figure.closest(excluded)) continue;
    const background =
      document.defaultView?.getComputedStyle(figure).backgroundImage ?? "";
    for (const match of background.matchAll(/url\(["']?([^"')]+)["']?\)/gi))
      images.push(url(match[1]));
  }
  const embeds = [
    ...root.querySelectorAll(
      "video[src],audio[src],source[src],iframe[src],object[data],embed[src]",
    ),
  ]
    .map((el) => ({
      url: url(el.getAttribute("src") ?? el.getAttribute("data")),
      kind: el.tagName.toLowerCase(),
    }))
    .filter((e) => e.url);
  const links = [...root.querySelectorAll("a[href]")]
    .map((el) => url(el.getAttribute("href")))
    .filter(Boolean);
  const copy = root.cloneNode(true);
  for (const el of copy.querySelectorAll(excluded + ",script,style"))
    el.remove();
  const text = copy.textContent.replace(/\s+/g, " ").trim();
  return {
    state: text.length >= 120 ? "article" : "needs-review",
    title,
    text,
    images: [...new Set(images.filter(Boolean))],
    embeds,
    links: [...new Set(links)],
  };
}
