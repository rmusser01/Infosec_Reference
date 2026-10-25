import { writeFileSync } from "node:fs";
import { readArticle } from "./article.mjs";

export default async function ({ page, data, crawler, seed, cdp }) {
  await crawler.loadPage(page, data, seed, cdp);
  if (process.env.ARCHIVE_STAGE === "capture") {
    await page.evaluate(() => {
      const root = document.querySelector('article,main,[role="main"]');
      for (const img of root?.querySelectorAll("img") ?? [])
        img.loading = "eager";
    });
    await page
      .waitForFunction(
        () =>
          [
            ...document.querySelectorAll(
              'article img,main img,[role="main"] img',
            ),
          ].every((img) => img.complete),
        { timeout: 5000 },
      )
      .catch(() => {});
  }
  await page
    .waitForFunction(
      () =>
        document.querySelector('article,main,[role="main"]')?.textContent
          .length >= 120,
      { timeout: 5000 },
    )
    .catch(() => {});
  const snapshot = await page.evaluate(readArticle);
  if (process.env.ARCHIVE_STAGE === "capture") {
    snapshot.imageFailures = await page.evaluate(async (urls) => {
      const results = await Promise.all(
        urls.map(async (url) => {
          const image = new Image();
          image.src = url;
          try {
            await Promise.race([
              image.decode(),
              new Promise((_, reject) =>
                setTimeout(() => reject(Error("Image timeout")), 5000),
              ),
            ]);
            return null;
          } catch {
            return url;
          }
        }),
      );
      return results.filter(Boolean);
    }, snapshot.images);
  }
  snapshot.url = page.url();
  snapshot.requestedUrl = data.url;
  writeFileSync(
    "/crawls/article.json",
    JSON.stringify(snapshot, null, 2) + "\n",
  );
}
