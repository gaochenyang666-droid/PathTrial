# PathTrial search discoverability checklist

Maintainer operations guide, reviewed 2026-10-21. No indexing, traffic, download or adoption results are claimed here.

## Existing public resources

- Website: https://gaochenyang666-droid.github.io/PathTrial/
- English: https://gaochenyang666-droid.github.io/PathTrial/en/
- Spanish: https://gaochenyang666-droid.github.io/PathTrial/es/
- Russian: https://gaochenyang666-droid.github.io/PathTrial/ru/
- Chinese troubleshooting hub: https://gaochenyang666-droid.github.io/PathTrial/guides/
- English troubleshooting hub: https://gaochenyang666-droid.github.io/PathTrial/en/guides/
- Sitemap: https://gaochenyang666-droid.github.io/PathTrial/sitemap.xml (13 HTML pages)
- Robots policy: https://gaochenyang666-droid.github.io/PathTrial/robots.txt
- Repository: https://github.com/gaochenyang666-droid/PathTrial
- Current public prerelease: https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1

## Google Search Console: owner steps

1. Go to https://search.google.com/search-console and add a URL-prefix property for https://gaochenyang666-droid.github.io/PathTrial/.
2. Choose an ownership verification method available for GitHub Pages. If provided with an HTML verification file, add that exact file to docs/ and redeploy. Never invent verification tokens.
3. Submit https://gaochenyang666-droid.github.io/PathTrial/sitemap.xml.
4. Use URL Inspection for the homepage, the English guide hub, and each of the three diagnostic tutorials.
5. Record indexed pages and non-branded search impressions weekly. A submitted sitemap does not guarantee that a URL is indexed.

## Bing Webmaster Tools: owner steps

1. Open https://www.bing.com/webmasters and verify the site, or import it from a verified Search Console property if supported.
2. Submit https://gaochenyang666-droid.github.io/PathTrial/sitemap.xml.
3. Inspect discovered URLs, coverage reports and crawl errors. Compare only data from the same date range.

## Site integrity checks

- Each of the 13 sitemap URLs should return HTTP 200 and use a self-referencing canonical.
- Ensure localized homepage and download pages still point to the correct release assets and language variants.
- Check guide cards and navigation on desktop and mobile.
- Review code samples against the released CLI help; avoid invented outputs and unsupported root-cause claims.
- Confirm GitHub Pages deployment success and source CI. Docs changes alone do not prove binary functionality.

## Repository and community discovery

- About already has a homepage, description and relevant topics, including rust, dns, quic, http3 and mcp-server.
- Consider additional accurate topics such as traceroute, ipv6 and network-troubleshooting if a repository administrator can update metadata.
- See community-launch-kit.md for optional draft posts. Disclose maintainer affiliation, respect each community's rules, and never buy backlinks, stars or reviews.
- Collect independent feedback, reproducible issues and technically substantive third-party reviews. Do not use Wikipedia as a promotional directory.

## Privacy and integrity

- Publish only real, verified diagnostic results, or explicitly label synthetic examples. No existing guide claims a successful public probe.
- Before sharing JSON reports, inspect names, addresses, local paths, credential fields and other metadata even if IP redaction is on.
- Search indexing, AI answer-engine citation and rankings are externally controlled outcomes, not guaranteed deliverables.
