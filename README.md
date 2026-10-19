# Lello Molinario — Professional Portfolio

Source for **https://lmolinario.github.io/**, a curated professional and research portfolio focused on:

- digital forensics and digital evidence;
- forensic acquisition and evidence-sensitive decision-making;
- cybersecurity and incident-oriented technical analysis;
- AI security and robustness of AI-assisted forensic workflows;
- selected applied security and OSINT projects.

## Primary public sections

- **About** — professional and research context
- **Research** — current experimental work and forward research directions
- **FAIR-Lab** — reproducible AI robustness evaluation for digital-forensic image classification
- **Projects** — curated portfolio of mature or meaningful public work
- **Evidence First** — author-side context for the *Evidence First — Digital Evidence Field Guides* series
- **Media & Editorial** — short biography and editorial background

The maintained publication website for Evidence First is **https://evidencefirst.guide/**.

## Portfolio policy

The public site intentionally distinguishes maintained work and current research from experimental utilities. Small prototypes may remain in the repository without being promoted as equal-weight professional outputs. Preview utilities that are not mature public products are excluded from search indexing.

## Structure

The site is static and deployed with GitHub Pages. Shared presentation rules for the primary portfolio pages are in `assets/site.css`. The responsive navigation, accessibility fixes and consistent footer are currently applied across the primary HTML pages.

### Automated quality gates

On pushes and pull requests, `.github/workflows/site-quality.yml` verifies the canonical URLs, title and description presence, semantic H1 elements, JSON-LD parsing, internal links, indexable sitemap URLs, and Python syntax. Run the same audit locally with:

```bash
python scripts/site_audit.py
```

The Open Graph artwork is maintained as `assets/social-card.svg`. `.github/workflows/render-social-card.yml` generates the `1200 x 630` PNG at `assets/social-card.png` automatically. Do not edit the PNG manually.

### Publications and SEO updates

When publishing a new externally hosted article, update `publications/index.html`, the latest-publication block on the homepage when applicable, associated structured metadata, and only the relevant `<lastmod>` dates in `sitemap.xml`. Preserve the publisher's original article as the content source. New canonical pages must also be added to `PUBLIC_PAGES` in `scripts/site_audit.py`.

### Applications and deployment safety

The Domain Risk Scan backend code under `tools/domain-risk-scan/` is not deployed by the static GitHub Pages workflow. Backend changes require independent tests and controlled deployment. Security changes remain in a separate draft pull request until endpoint authorization, staging tests, and production configuration have been verified.

## Copyright

Unless a file or linked project states otherwise, website text, graphics, research summaries and editorial material are © Lello Molinario. See the site's Legal Notice for details.
