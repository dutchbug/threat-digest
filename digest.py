#!/usr/bin/env python3
"""Threat digest: collect security news and CISA KEV data, tag it, and build a static website.

Usage:
    python digest.py                                  # live feeds (what GitHub Actions runs)
    python digest.py --fixtures tests/fixtures --now 2026-11-05T12:00:00Z   # offline test data

Output:
    data/daily/YYYY-MM-DD.json   collected items per day (the history)
    data/seen.json               item IDs already published (prevents duplicates)
    docs/                        the website (served by GitHub Pages)
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import feedparser
import markdown
import requests
import yaml

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DAILY = DATA / "daily"
DOCS = ROOT / "docs"
POSTS = ROOT / "posts"
SEEN_FILE = DATA / "seen.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "threat-digest/1.0 (personal open-source project)"
TIMEOUT = 20          # seconds per request
SEEN_DAYS = 30        # how long to remember published items
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TRACKING_PARAM = re.compile(r"^(utm_|fbclid$|gclid$|mc_)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def esc(value) -> str:
    """Escape text for HTML. Feed content is untrusted input, so everything shown goes through this."""
    return html.escape(str(value), quote=True)


def safe_url(url: str) -> str:
    """Allow only http(s) links, so a malicious feed can't inject javascript: or data: links."""
    url = (url or "").strip()
    return url if urlsplit(url).scheme in ("http", "https") else ""


def normalize_link(url: str) -> str:
    """Normalize a URL for duplicate detection (lowercase host, no tracking params, no trailing slash)."""
    parts = urlsplit(url)
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not TRACKING_PARAM.match(k)])
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def item_id(url: str) -> str:
    return hashlib.sha1(normalize_link(url).encode()).hexdigest()[:16]


def clean_text(value: str) -> str:
    """Strip HTML tags and collapse whitespace."""
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def compile_keywords(words: list[str]) -> re.Pattern | None:
    """Build one case-insensitive regex that matches whole words (so 'rat' doesn't match 'pirate')."""
    parts = []
    for word in words:
        word = word.lower().strip()
        if not word:
            continue
        pattern = re.escape(word)
        if word[0].isalnum():
            pattern = r"(?<![a-z0-9])" + pattern
        if word[-1].isalnum():
            pattern += r"(?![a-z0-9])"
        parts.append(pattern)
    return re.compile("|".join(parts)) if parts else None


def load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fetch(source_id: str, url: str, fixtures: Path | None, suffix: str) -> bytes:
    """Download a source, or read it from the fixtures folder when testing offline."""
    if fixtures:
        path = fixtures / f"{source_id}{suffix}"
        if not path.exists():
            raise FileNotFoundError(f"no fixture file {path.name}")
        return path.read_bytes()
    response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    response.raise_for_status()
    return response.content


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

class Tagger:
    def __init__(self, cfg: dict):
        self.tags = {name: compile_keywords(words) for name, words in cfg.get("tags", {}).items()}
        self.watch = {term: compile_keywords([term]) for term in cfg.get("watchlist", [])}

    def tag(self, text: str) -> list[str]:
        text = text.lower()
        return [name for name, rx in self.tags.items() if rx and rx.search(text)]

    def watch_hits(self, text: str) -> list[str]:
        text = text.lower()
        return [term for term, rx in self.watch.items() if rx and rx.search(text)]


def entry_time(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        value = entry.get(key)
        if value:
            return datetime(*value[:6], tzinfo=timezone.utc)
    return None


def collect_feeds(cfg: dict, tagger: Tagger, fixtures: Path | None, now: datetime):
    cutoff = now - timedelta(hours=cfg.get("lookback_hours", 48))
    items, health = [], []
    for feed in cfg.get("feeds", []):
        status = {"id": feed["id"], "name": feed["name"], "status": "ok", "items": 0}
        try:
            parsed = feedparser.parse(fetch(feed["id"], feed["url"], fixtures, ".xml"))
            if parsed.bozo and not parsed.entries:
                raise ValueError(f"could not parse feed ({parsed.get('bozo_exception')})")
            for entry in parsed.entries:
                link = safe_url(entry.get("link", ""))
                title = clean_text(entry.get("title", ""))
                if not link or not title:
                    continue
                published = min(entry_time(entry) or now, now)  # clamp future dates
                if published < cutoff:
                    continue
                # The summary is only used for tagging. It is NOT republished (copyright):
                # the site shows the headline, source and a link to the original.
                text = f"{title} {clean_text(entry.get('summary', ''))}"
                items.append({
                    "id": item_id(link),
                    "title": title[:300],
                    "link": link,
                    "source": feed["name"],
                    "published": published.isoformat(),
                    "tags": tagger.tag(text),
                    "watch": tagger.watch_hits(text),
                })
                status["items"] += 1
        except Exception as exc:  # one broken feed must not stop the whole run
            status.update(status="error", error=str(exc)[:200])
            print(f"warning: {feed['name']}: {exc}", file=sys.stderr)
        health.append(status)
    return items, health


def collect_kev(cfg: dict, tagger: Tagger, fixtures: Path | None, today: date):
    status = {"id": "cisa-kev", "name": "CISA Known Exploited Vulnerabilities", "status": "ok", "items": 0}
    entries = []
    try:
        data = json.loads(fetch("kev", KEV_URL, fixtures, ".json"))
        cutoff = today - timedelta(days=cfg.get("kev_days", 7))
        for vuln in data.get("vulnerabilities", []):
            cve = str(vuln.get("cveID", "")).strip()
            try:
                added = date.fromisoformat(vuln.get("dateAdded", ""))
            except ValueError:
                continue
            if added < cutoff or not CVE_RE.match(cve):
                continue
            text = " ".join(str(vuln.get(k, "")) for k in ("vendorProject", "product", "vulnerabilityName"))
            entries.append({
                "cve": cve,
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "description": vuln.get("shortDescription", ""),
                "action": vuln.get("requiredAction", ""),
                "added": added.isoformat(),
                "due": vuln.get("dueDate", ""),
                "ransomware": vuln.get("knownRansomwareCampaignUse", "") == "Known",
                "watch": tagger.watch_hits(text),
            })
        entries.sort(key=lambda v: (v["added"], v["cve"]), reverse=True)
        status["items"] = len(entries)
        status["catalog_version"] = data.get("catalogVersion", "")
    except Exception as exc:
        status.update(status="error", error=str(exc)[:200])
        print(f"warning: CISA KEV: {exc}", file=sys.stderr)
    return entries, status


def update_data(cfg: dict, fixtures: Path | None, now: datetime) -> None:
    tz = ZoneInfo(cfg["site"].get("timezone", "UTC"))
    today = now.astimezone(tz).date()
    tagger = Tagger(cfg)

    items, health = collect_feeds(cfg, tagger, fixtures, now)
    kev, kev_health = collect_kev(cfg, tagger, fixtures, today)
    health.insert(0, kev_health)

    # Remove duplicates: within this run, and items already published on earlier runs.
    seen = load_json(SEEN_FILE, {})
    day_file = DAILY / f"{today.isoformat()}.json"
    day = load_json(day_file, {"date": today.isoformat(), "items": [], "kev": []})
    new_items = []
    for item in sorted(items, key=lambda i: i["published"], reverse=True):
        if item["id"] in seen:
            continue
        seen[item["id"]] = today.isoformat()
        new_items.append(item)

    # Running again on the same day adds new items to that day instead of replacing it.
    day["items"] = new_items + day["items"]
    if kev_health["status"] == "ok":
        day["kev"] = kev
    day["health"] = health
    day["generated_at"] = now.isoformat()
    write_json(day_file, day)

    keep_after = (today - timedelta(days=SEEN_DAYS)).isoformat()
    write_json(SEEN_FILE, {k: v for k, v in seen.items() if v >= keep_after})
    print(f"{today}: {len(new_items)} new items, {len(kev)} KEV entries, "
          f"{sum(h['status'] == 'error' for h in health)} source errors")


# ---------------------------------------------------------------------------
# Build the website
# ---------------------------------------------------------------------------

def page(cfg: dict, title: str, body: str, depth: int = 0) -> str:
    root = "../" * depth
    site = cfg["site"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{esc(site.get('description', ''))}">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:">
<meta name="referrer" content="no-referrer">
<title>{esc(title)} · {esc(site['title'])}</title>
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header class="top">
  <a class="brand" href="{root}index.html">{esc(site['title'])}</a>
  <nav>
    <a href="{root}index.html">Today</a>
    <a href="{root}archive/index.html">Archive</a>
    <a href="{root}weekly/index.html">Weekly analysis</a>
    <a href="{root}about.html">About</a>
  </nav>
</header>
<main>
{body}
</main>
<footer>
  <p>Built by {esc(site.get('author', ''))}. Headlines link to the original sources; summaries are not republished.
  Vulnerability data: CISA Known Exploited Vulnerabilities catalog.</p>
</footer>
<script src="{root}filter.js"></script>
</body>
</html>
"""


def fmt_time(iso: str, tz: ZoneInfo) -> str:
    dt = datetime.fromisoformat(iso).astimezone(tz)
    return dt.strftime("%b %d, %I:%M %p").replace(" 0", " ")


def badge(text: str, kind: str = "tag") -> str:
    return f'<span class="badge {kind}">{esc(text)}</span>'


def render_day(cfg: dict, day: dict, tz: ZoneInfo) -> str:
    items, kev = day.get("items", []), day.get("kev", [])
    watch_count = sum(bool(i["watch"]) for i in items) + sum(bool(v["watch"]) for v in kev)
    kev_days = cfg.get("kev_days", 7)
    day_label = date.fromisoformat(day["date"]).strftime("%A, %B %d, %Y").replace(" 0", " ")

    parts = [f'<h1>{esc(day_label)}</h1>']
    if day.get("generated_at"):
        parts.append(f'<p class="muted">Last updated {esc(fmt_time(day["generated_at"], tz))} · collected automatically</p>')

    parts.append(f"""<section class="stats">
  <div class="stat"><span>New items</span><strong>{len(items)}</strong></div>
  <div class="stat"><span>KEV added (last {kev_days} days)</span><strong class="danger">{len(kev)}</strong></div>
  <div class="stat"><span>Watchlist hits</span><strong class="warning">{watch_count}</strong></div>
</section>""")

    # Actively exploited vulnerabilities
    parts.append(f'<h2>Actively exploited (CISA KEV, last {kev_days} days)</h2>')
    if kev:
        rows = []
        for v in kev:
            flags = "".join(badge(w, "watch") for w in v["watch"])
            if v["ransomware"]:
                flags += badge("used in ransomware", "danger")
            nvd = f"https://nvd.nist.gov/vuln/detail/{v['cve']}"
            rows.append(f"""<li class="card">
  <div class="row"><a class="mono" href="{esc(nvd)}" rel="noopener noreferrer">{esc(v['cve'])}</a>
  <span class="muted">added {esc(v['added'])} · fix by {esc(v['due'])}</span></div>
  <div class="title">{esc(v['name'] or f"{v['vendor']} {v['product']}")}</div>
  <p class="muted">{esc(v['description'])}</p>
  <div class="badges">{flags}</div>
</li>""")
        parts.append(f'<ul class="list">{"".join(rows)}</ul>')
    else:
        parts.append('<p class="muted">No new KEV entries in this period.</p>')

    # Headlines: watchlist hits first, then newest first
    parts.append("<h2>Headlines</h2>")
    if items:
        all_tags = sorted({t for i in items for t in i["tags"]})
        buttons = "".join(f'<button type="button" data-tag="{esc(t)}">{esc(t)}</button>' for t in all_tags)
        parts.append(f'<div class="filters" aria-label="Filter by tag"><button type="button" data-tag="" class="active">all</button>{buttons}</div>')
        rows = []
        ordered = sorted(items, key=lambda i: i["published"], reverse=True)
        ordered.sort(key=lambda i: not i["watch"])  # stable sort keeps newest-first within groups
        for i in ordered:
            badges = "".join(badge(t) for t in i["tags"]) + "".join(badge(w, "watch") for w in i["watch"])
            rows.append(f"""<li class="card" data-tags="{esc('|'.join(i['tags']))}">
  <a class="title" href="{esc(i['link'])}" rel="noopener noreferrer">{esc(i['title'])}</a>
  <div class="muted">{esc(i['source'])} · {esc(fmt_time(i['published'], tz))}</div>
  <div class="badges">{badges}</div>
</li>""")
        parts.append(f'<ul class="list" id="headlines">{"".join(rows)}</ul>')
    else:
        parts.append('<p class="muted">No new headlines in this run.</p>')

    # Source health: shows which feeds worked, like a small monitoring panel
    rows = []
    for h in day.get("health", []):
        state = badge("ok", "ok") if h["status"] == "ok" else badge("error", "danger")
        detail = f'{h["items"]} items' if h["status"] == "ok" else esc(h.get("error", ""))
        rows.append(f"<tr><td>{esc(h['name'])}</td><td>{state}</td><td class=\"muted\">{detail}</td></tr>")
    if rows:
        parts.append(f'<details class="health"><summary>Source status</summary><table>{"".join(rows)}</table></details>')
    return "\n".join(parts)


def load_posts() -> list[dict]:
    posts = []
    for path in sorted(POSTS.glob("*.md"), reverse=True):
        if path.name.startswith("_"):
            continue  # templates and drafts
        text = path.read_text(encoding="utf-8")
        match = re.match(r"^#\s+(.+)$", text, re.M)
        title = match.group(1).strip() if match else path.stem
        body = re.sub(r"^#\s+.+\n", "", text, count=1, flags=re.M) if match else text
        date_match = re.match(r"(\d{4}-\d{2}-\d{2})", path.stem)
        posts.append({
            "slug": path.stem,
            "title": title,
            "date": date_match.group(1) if date_match else "",
            # Posts are written by you, so Markdown is rendered as-is (trusted content).
            "html": markdown.markdown(body, extensions=["tables", "fenced_code"]),
        })
    return posts


def build_site(cfg: dict) -> None:
    tz = ZoneInfo(cfg["site"].get("timezone", "UTC"))
    days = [load_json(p, {}) for p in sorted(DAILY.glob("*.json"), reverse=True)]
    posts = load_posts()
    (DOCS / "archive").mkdir(parents=True, exist_ok=True)
    (DOCS / "weekly").mkdir(parents=True, exist_ok=True)
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")

    def write(rel: str, content: str) -> None:
        (DOCS / rel).write_text(content, encoding="utf-8")

    # Home page: latest weekly post + today's digest
    latest_post = ""
    if posts:
        p = posts[0]
        latest_post = f"""<a class="post-teaser" href="weekly/{esc(p['slug'])}.html">
  <span class="muted">Latest weekly analysis · {esc(p['date'])}</span>
  <strong>{esc(p['title'])}</strong>
</a>"""
    home = render_day(cfg, days[0], tz) if days else "<h1>No data yet</h1><p>Run the workflow once to collect the first digest.</p>"
    write("index.html", page(cfg, "Today", latest_post + home))

    # Archive: one page per day
    links = []
    for day in days:
        write(f"archive/{day['date']}.html", page(cfg, day["date"], render_day(cfg, day, tz), depth=1))
        links.append(f'<li><a href="{esc(day["date"])}.html">{esc(day["date"])}</a> '
                     f'<span class="muted">{len(day.get("items", []))} items · {len(day.get("kev", []))} KEV</span></li>')
    write("archive/index.html", page(cfg, "Archive", f'<h1>Archive</h1><ul class="plain">{"".join(links)}</ul>', depth=1))

    # Weekly analysis posts
    post_links = []
    for p in posts:
        body = f'<article class="post"><p class="muted">{esc(p["date"])} · written by {esc(cfg["site"].get("author", ""))}</p><h1>{esc(p["title"])}</h1>{p["html"]}</article>'
        write(f"weekly/{p['slug']}.html", page(cfg, p["title"], body, depth=1))
        post_links.append(f'<li><a href="{esc(p["slug"])}.html">{esc(p["title"])}</a> <span class="muted">{esc(p["date"])}</span></li>')
    weekly = "<h1>Weekly analysis</h1>" + (f'<ul class="plain">{"".join(post_links)}</ul>' if post_links else '<p class="muted">No posts yet.</p>')
    write("weekly/index.html", page(cfg, "Weekly analysis", weekly, depth=1))

    # About page
    sources = "".join(f'<li>{esc(f["name"])}</li>' for f in cfg.get("feeds", []))
    about = f"""<h1>About</h1>
<p>{esc(cfg['site'].get('description', ''))}</p>
<p>Every morning a scheduled GitHub Actions job collects the sources below, removes duplicates,
tags items by topic, highlights technology on my watchlist and rebuilds this site.
Weekly analysis posts are written by me.</p>
<h2>Sources</h2><ul class="plain">{sources}<li>CISA Known Exploited Vulnerabilities catalog</li></ul>"""
    write("about.html", page(cfg, "About", about))


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fixtures", type=Path, help="read sources from this folder instead of the internet")
    parser.add_argument("--now", help="override the current time (ISO format), for testing")
    parser.add_argument("--build-only", action="store_true", help="rebuild the site without collecting new data")
    args = parser.parse_args()

    cfg = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else datetime.now(timezone.utc)
    if not args.build_only:
        update_data(cfg, args.fixtures, now)
    build_site(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
