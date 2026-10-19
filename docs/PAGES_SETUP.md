# PathTrial GitHub Pages

The static website source lives directly in `docs/`. It does not require
Node, Jekyll, a framework, paid hosting, or third-party tracking.

## One-time activation by repository owner

1. Open [Settings → Pages](https://github.com/gaochenyang666-droid/PathTrial/settings/pages).
2. Under **Build and deployment**, select **Deploy from a branch**.
3. Choose **Branch: `main`** and **Folder: `/docs`**, then **Save**.
4. After GitHub completes the Pages build, visit
   **https://gaochenyang666-droid.github.io/PathTrial/**.
5. Check the [download page](https://gaochenyang666-droid.github.io/PathTrial/download.html)
   and confirm its three archive links and matching SHA-256 files.
6. Optionally add that verified live site URL to the repository **About → Website**
   field. Do not set the URL until the Pages site is accessible.

The expected project-site URL is based on the GitHub repository owner and name.
If a custom domain or a different Pages source is configured, update canonical
URLs in `docs/index.html` and `docs/download.html`, as well as the sitemap.

## Files

- `index.html` — product homepage and MCP overview.
- `download.html` — downloads, checksum links, installation.
- `site.css` — responsive styling.
- `.nojekyll` — publish static files without Jekyll transformations.
- `robots.txt`, `sitemap.xml` — crawler instructions and canonical pages.

## Maintenance

Whenever the public release changes, update links and version strings
in both HTML pages, the sitemap if page paths change, and the README.
Only link to assets confirmed in the published GitHub Release. The website
does not install software in the browser or run diagnostics on visitors.
Do not include private addresses, telemetry tokens, or credentials.

## Translated website pages

The default URLs remain Simplified Chinese. Static English, Spanish and Russian pages are served from `docs/en/`, `docs/es/`, and `docs/ru/` respectively. Each locale has an `index.html` and `download.html`. Use the header language switcher on either page; every page includes canonical and hreflang links, and `docs/sitemap.xml` lists all eight URLs. Updating a README translation alone does not translate GitHub Pages.

When changing the public release, update all four localized download pages and the Chinese download page, as well as all four READMEs. Verify published assets before changing URLs; keep the historical releases untouched.
