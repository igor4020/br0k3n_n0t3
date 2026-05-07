# Cyber notes

A minimalist, paper-journal cybersecurity blog by Igor Benevides.
Built with [Jekyll](https://jekyllrb.com/), markdown-first, ready for **GitHub Pages**.

## Stack

- Jekyll 4 + kramdown + Rouge for syntax highlighting
- Patrick Hand (handwritten body) + JetBrains Mono (code) — Google Fonts
- Pure CSS — dotted journal background, macOS-style code windows
- Plugins: `jekyll-feed`, `jekyll-seo-tag`, `jekyll-sitemap`

## Local preview

```bash
bundle install
bundle exec jekyll serve --livereload
# open http://localhost:4000
```

## Writing a post

Drop a markdown file in `_posts/` named `YYYY-MM-DD-slug.md`:

```markdown
---
title: "My new post"
date: 2026-05-01 09:00:00 -0300
read_time: 5
tags: [maldev, notes]
excerpt: "One-line summary that shows on the home page."
---

Body in markdown. Triple-backtick code blocks render in
the macOS-style window automatically (Rouge does the highlighting).
```

Available tags propagate to `/tags/` automatically.

## Deploying to GitHub Pages

There are two common setups. Pick one.

### A. Project site at `https://<user>.github.io/<repo>`

1. Push this folder to a new repo, e.g. `cyber-notes`.
2. Open `_config.yml` and set:
   ```yaml
   url:     "https://<user>.github.io"
   baseurl: "/cyber-notes"
   ```
3. In the repo settings → **Pages** → set Source to `Deploy from a branch`, branch `main`, folder `/ (root)`.
4. GitHub Pages will build with Jekyll automatically. First build takes a minute.

### B. User site at `https://<user>.github.io` (or custom domain)

1. Repo must be named `<user>.github.io`.
2. Leave `url` and `baseurl` blank in `_config.yml` (already set this way).
3. Same Pages settings — `main` branch, root folder.
4. For a custom domain, add a `CNAME` file at the project root containing your domain.

### Optional: GitHub Actions build

If you want full control over the Jekyll version, add `.github/workflows/jekyll.yml`
using the official `actions/jekyll-build-pages` action. Not required for the default
GH Pages build.

## Layout overview

```
_config.yml          — site config
_layouts/            — default / post / page
_includes/           — head, header, footer
_posts/              — your markdown posts
assets/css/main.css  — the whole theme; tweak colors at the top
index.html           — homepage post listing
about.md             — about page
tags.html            — tags + archive
```

Theme tokens live at the top of `assets/css/main.css` under `:root` —
change `--paper`, `--accent`, `--ink` etc. in one place.
