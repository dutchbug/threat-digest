#!/usr/bin/env python3
"""Threat digest: collect security news, research and CISA KEV data, tag it, and build a static website.

Usage:
    python digest.py                                  # live feeds (what GitHub Actions runs)
    python digest.py --fixtures tests/fixtures --now 2026-11-05T12:00:00Z   # offline test data
    python digest.py --build-only                     # rebuild the site from saved data

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

# Filter groups: (key in item data, key in config, label on the site)
GROUPS = [
    ("tags", "tags", "Topics"),
    ("sectors", "sectors", "Sectors"),
    ("regulations", "regulations", "Regulations and standards"),
]
SOURCE_TYPES = {"news": "News", "research": "Threat research", "government": "Government", "analysis": "Analysis"}


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
        word = str(word).lower().strip()
        if not word:
            continue
        pattern = re.escape(word)
        if word[0].isalnum():
            pattern = r"(?<![a-z0-9])" + pattern
        if word[-1].isalnum():
            pattern += r"(?![a-z0-9])"
        parts.append(pattern)
    return re.compile("|".join(parts)) if parts else None


def json_for_script(data) -> str:
    """JSON that is safe to place inside a <script> element (no '</script>' breakout)."""
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


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
# Tagging
# ---------------------------------------------------------------------------

class Tagger:
    """Keyword tagging for topics, sectors, regulations and the watchlist."""

    def __init__(self, cfg: dict):
        self.groups = {
            key: {name: compile_keywords(words) for name, words in (cfg.get(cfg_key) or {}).items()}
            for key, cfg_key, _ in GROUPS
        }
        self.watch = {term: compile_keywords([term]) for term in cfg.get("watchlist", [])}

    def analyze(self, text: str) -> dict:
        text = text.lower()
        result = {key: [name for name, rx in rules.items() if rx and rx.search(text)]
                  for key, rules in self.groups.items()}
        result["watch"] = [term for term, rx in self.watch.items() if rx and rx.search(text)]
        return result


def feed_types(cfg: dict) -> dict:
    return {f["name"]: f.get("type", "news") for f in cfg.get("feeds", [])}


def enrich(item: dict, tagger: Tagger, types: dict) -> dict:
    """Fill fields that older data files don't have yet (tags from the title only)."""
    missing = [k for k, _, _ in GROUPS if k not in item] + (["watch"] if "watch" not in item else [])
    if missing:
        found = tagger.analyze(item["title"])
        for key in missing:
            item[key] = found[key]
    item.setdefault("type", types.get(item.get("source"), "news"))
    return item


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

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
                # The summary is only used for tagging. It is NOT stored or republished (copyright):
                # the site shows the headline, source and a link to the original.
                found = tagger.analyze(f"{title} {clean_text(entry.get('summary', ''))}")
                items.append({
                    "id": item_id(link),
                    "title": title[:300],
                    "link": link,
                    "source": feed["name"],
                    "type": feed.get("type", "news"),
                    "published": published.isoformat(),
                    **found,
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
                "watch": tagger.analyze(text)["watch"],
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
# Profiles
# ---------------------------------------------------------------------------

def load_profiles(cfg: dict) -> list[dict]:
    """Read preset profiles from config and warn about names that don't exist."""
    known = {
        "topics": set(cfg.get("tags") or {}),
        "sectors": set(cfg.get("sectors") or {}),
        "regulations": set(cfg.get("regulations") or {}),
        "types": set(SOURCE_TYPES),
    }
    profiles = []
    for raw in cfg.get("profiles") or []:
        profile = {"name": str(raw.get("name", "Unnamed")), "match": "all" if raw.get("match") == "all" else "any",
                   "watch": bool(raw.get("watch", False)), "q": str(raw.get("search", ""))}
        for group, names in known.items():
            values = [str(v) for v in raw.get(group) or []]
            unknown = [v for v in values if v not in names]
            if unknown:
                print(f"warning: profile '{profile['name']}': unknown {group}: {unknown}", file=sys.stderr)
            profile[group] = [v for v in values if v in names]
        profiles.append(profile)
    return profiles


# ---------------------------------------------------------------------------
# Build the website
# ---------------------------------------------------------------------------

def page(cfg: dict, title: str, body: str, depth: int = 0, profiles: list | None = None) -> str:
    root = "../" * depth
    site = cfg["site"]
    profile_data = (f'<script type="application/json" id="profiles-data">{json_for_script(profiles)}</script>\n'
                    if profiles is not None else "")
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
    <a href="{root}recent.html">Last 7 days</a>
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
  Vulnerability data: CISA Known Exploited Vulnerabilities catalog. Sector and regulation tags are keyword-based hints, not compliance advice.</p>
</footer>
{profile_data}<script src="{root}app.js"></script>
</body>
</html>
"""


def fmt_time(iso: str, tz: ZoneInfo) -> str:
    dt = datetime.fromisoformat(iso).astimezone(tz)
    return dt.strftime("%b %d, %I:%M %p").replace(" 0", " ")


def badge(text: str, kind: str = "tag") -> str:
    return f'<span class="badge {kind}">{esc(text)}</span>'


def render_filters(cfg: dict, items: list[dict]) -> str:
    """Filter panel. Hidden until app.js runs, so the page still works without JavaScript."""
    groups_html = []
    for key, cfg_key, label in GROUPS:
        chips = []
        for name in (cfg.get(cfg_key) or {}):
            count = sum(name in i.get(key, []) for i in items)
            chips.append(f'<button type="button" class="chip{" empty" if not count else ""}" data-group="{"topics" if key == "tags" else key}" '
                         f'data-value="{esc(name)}" aria-pressed="false">{esc(name)} <span class="count">{count}</span></button>')
        groups_html.append(f'<div class="chip-group"><span class="group-label">{esc(label)}</span><div class="chips">{"".join(chips)}</div></div>')
    type_chips = "".join(
        f'<button type="button" class="chip" data-group="types" data-value="{esc(t)}" aria-pressed="false">{esc(label)} '
        f'<span class="count">{sum(i.get("type") == t for i in items)}</span></button>'
        for t, label in SOURCE_TYPES.items())
    groups_html.append(f'<div class="chip-group"><span class="group-label">Source type</span><div class="chips">{type_chips}</div></div>')

    return f"""<section class="filter-panel" id="filters" hidden aria-label="Filters">
  <div class="filter-row">
    <label for="profile-select" class="group-label">Profile</label>
    <select id="profile-select"></select>
    <button type="button" id="profile-delete" hidden>Delete profile</button>
    <button type="button" id="copy-link">Copy link</button>
    <button type="button" id="clear-filters">Clear filters</button>
  </div>
  <div class="filter-row">
    <input type="search" id="filter-search" placeholder="Search headlines, for example fortinet" aria-label="Search headlines">
    <label class="inline"><input type="checkbox" id="filter-watch"> Watchlist only</label>
    <span class="inline match" role="radiogroup" aria-label="Match mode">Match
      <label class="inline"><input type="radio" name="match" value="any" checked> any filter</label>
      <label class="inline"><input type="radio" name="match" value="all"> every group</label>
    </span>
  </div>
  {"".join(groups_html)}
  <div class="filter-row">
    <input type="text" id="profile-name" maxlength="60" placeholder="Name this filter set, for example Healthcare SOC" aria-label="Profile name">
    <button type="button" id="profile-save">Save as profile</button>
    <span id="profile-msg" class="msg" role="status"></span>
  </div>
  <p class="hint">Saved profiles are stored in this browser only. Use "Copy link" to open the same filters on another device.
  Sector and regulation tags are keyword-based hints, not a compliance assessment.</p>
</section>
<p id="filter-status" class="muted" role="status"></p>"""


def render_item(item: dict, tz: ZoneInfo) -> str:
    badges = ("".join(badge(t) for t in item.get("tags", []))
              + "".join(badge(s, "sector") for s in item.get("sectors", []))
              + "".join(badge(r, "reg") for r in item.get("regulations", []))
              + "".join(badge(w, "watch") for w in item.get("watch", [])))
    attrs = {
        "data-topics": "|".join(item.get("tags", [])),
        "data-sectors": "|".join(item.get("sectors", [])),
        "data-regulations": "|".join(item.get("regulations", [])),
        "data-type": item.get("type", "news"),
        "data-watch": "1" if item.get("watch") else "0",
        "data-search": f"{item['title']} {item['source']}".lower(),
        "data-published": item["published"],
    }
    attr_html = " ".join(f'{k}="{esc(v)}"' for k, v in attrs.items())
    type_label = SOURCE_TYPES.get(item.get("type", "news"), "News")
    return f"""<li class="card item" {attr_html}>
  <a class="title" href="{esc(item['link'])}" rel="noopener noreferrer">{esc(item['title'])}</a>
  <div class="muted">{esc(item['source'])} · {esc(type_label)} · {esc(fmt_time(item['published'], tz))}</div>
  <div class="badges">{badges}</div>
</li>"""


def render_listing(cfg: dict, heading: str, subtitle: str, items: list[dict], kev: list[dict],
                   health: list[dict], tz: ZoneInfo) -> str:
    kev_days = cfg.get("kev_days", 7)
    research = [i for i in items if i.get("type") == "research"]
    headlines = [i for i in items if i.get("type") != "research"]
    watch_count = sum(bool(i.get("watch")) for i in items) + sum(bool(v.get("watch")) for v in kev)

    parts = [f"<h1>{esc(heading)}</h1>"]
    if subtitle:
        parts.append(f'<p class="muted">{esc(subtitle)} <span id="new-since"></span></p>')
    parts.append(f"""<section class="stats">
  <div class="stat"><span>Headlines</span><strong>{len(headlines)}</strong></div>
  <div class="stat"><span>Research reports</span><strong>{len(research)}</strong></div>
  <div class="stat"><span>KEV added (last {kev_days} days)</span><strong class="danger">{len(kev)}</strong></div>
  <div class="stat"><span>Watchlist hits</span><strong class="warning">{watch_count}</strong></div>
</section>""")

    # Actively exploited vulnerabilities
    parts.append(f"<h2>Actively exploited (CISA KEV, last {kev_days} days)</h2>")
    if kev:
        rows = []
        for v in kev:
            flags = "".join(badge(w, "watch") for w in v["watch"])
            if v["ransomware"]:
                flags += badge("used in ransomware", "danger")
            nvd = f"https://nvd.nist.gov/vuln/detail/{v['cve']}"
            search = f"{v['cve']} {v['vendor']} {v['product']} {v['name']}".lower()
            rows.append(f"""<li class="card kev" data-watch="{'1' if v['watch'] else '0'}" data-search="{esc(search)}">
  <div class="row"><a class="mono" href="{esc(nvd)}" rel="noopener noreferrer">{esc(v['cve'])}</a>
  <span class="muted">added {esc(v['added'])} · fix by {esc(v['due'])}</span></div>
  <div class="title">{esc(v['name'] or f"{v['vendor']} {v['product']}")}</div>
  <p class="muted">{esc(v['description'])}</p>
  <div class="badges">{flags}</div>
</li>""")
        parts.append(f'<ul class="list" id="kev-list">{"".join(rows)}</ul>')
        parts.append('<p class="muted empty-msg" data-for="kev-list" hidden>No KEV entries match your search or watchlist filter.</p>')
    else:
        parts.append('<p class="muted">No new KEV entries in this period.</p>')

    parts.append(render_filters(cfg, items))

    for list_id, title, group in (("headlines", "Headlines", headlines), ("research", "Threat research", research)):
        parts.append(f"<h2>{title}</h2>")
        if group:
            ordered = sorted(group, key=lambda i: i["published"], reverse=True)
            ordered.sort(key=lambda i: not i.get("watch"))  # watchlist hits first, newest first within groups
            parts.append(f'<ul class="list" id="{list_id}">{"".join(render_item(i, tz) for i in ordered)}</ul>')
            parts.append(f'<p class="muted empty-msg" data-for="{list_id}" hidden>No items match these filters.</p>')
        else:
            parts.append(f'<p class="muted">No {title.lower()} in this period.</p>')

    # Source health: shows which feeds worked, like a small monitoring panel
    rows = []
    for h in health:
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
    tagger, types = Tagger(cfg), feed_types(cfg)
    profiles = load_profiles(cfg)
    days = [load_json(p, {}) for p in sorted(DAILY.glob("*.json"), reverse=True)]
    for day in days:
        day["items"] = [enrich(i, tagger, types) for i in day.get("items", [])]
    posts = load_posts()
    (DOCS / "archive").mkdir(parents=True, exist_ok=True)
    (DOCS / "weekly").mkdir(parents=True, exist_ok=True)
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")

    def write(rel: str, content: str) -> None:
        (DOCS / rel).write_text(content, encoding="utf-8")

    def day_heading(day: dict) -> str:
        return date.fromisoformat(day["date"]).strftime("%A, %B %d, %Y").replace(" 0", " ")

    def updated(day: dict) -> str:
        return f"Last updated {fmt_time(day['generated_at'], tz)} · collected automatically" if day.get("generated_at") else ""

    # Home page: latest weekly post + today's digest
    latest_post = ""
    if posts:
        p = posts[0]
        latest_post = f"""<a class="post-teaser" href="weekly/{esc(p['slug'])}.html">
  <span class="muted">Latest weekly analysis · {esc(p['date'])}</span>
  <strong>{esc(p['title'])}</strong>
</a>"""
    if days:
        d = days[0]
        home = render_listing(cfg, day_heading(d), updated(d), d["items"], d.get("kev", []), d.get("health", []), tz)
    else:
        home = "<h1>No data yet</h1><p>Run the workflow once to collect the first digest.</p>"
    write("index.html", page(cfg, "Today", latest_post + home, profiles=profiles))

    # Last N days in one list (handy with profiles)
    recent_n = cfg.get("recent_days", 7)
    recent = days[:recent_n]
    if recent:
        items = [i for d in recent for i in d["items"]]
        span = f"{recent[-1]['date']} to {recent[0]['date']}"
        body = render_listing(cfg, f"Last {recent_n} days", f"{span} · {updated(recent[0])}", items,
                              recent[0].get("kev", []), recent[0].get("health", []), tz)
    else:
        body = "<h1>No data yet</h1>"
    write("recent.html", page(cfg, f"Last {recent_n} days", body, profiles=profiles))

    # Archive: one page per day
    links = []
    for day in days:
        body = render_listing(cfg, day_heading(day), updated(day), day["items"], day.get("kev", []), day.get("health", []), tz)
        write(f"archive/{day['date']}.html", page(cfg, day["date"], body, depth=1, profiles=profiles))
        links.append(f'<li><a href="{esc(day["date"])}.html">{esc(day["date"])}</a> '
                     f'<span class="muted">{len(day["items"])} items · {len(day.get("kev", []))} KEV</span></li>')
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
    by_type = {}
    for f in cfg.get("feeds", []):
        by_type.setdefault(SOURCE_TYPES.get(f.get("type", "news"), "News"), []).append(f["name"])
    sources = "".join(f'<h3>{esc(t)}</h3><ul class="plain">{"".join(f"<li>{esc(n)}</li>" for n in names)}</ul>'
                      for t, names in by_type.items())
    preset_list = "".join(f"<li>{esc(p['name'])}</li>" for p in profiles)
    about = f"""<h1>About</h1>
<p>{esc(cfg['site'].get('description', ''))}</p>
<p>Every morning a scheduled GitHub Actions job collects the sources below, removes duplicates,
tags items by topic, sector and regulation, highlights technology on my watchlist and rebuilds this site.
Weekly analysis posts are written by me.</p>
<h2>Filters and profiles</h2>
<p>Use the filter panel to narrow the list by topic, sector, regulation or source type. Profiles are saved filter sets,
for example for a specific job or industry. Preset profiles:</p>
<ul class="plain">{preset_list}</ul>
<p>You can save your own profiles; they are stored in your browser only.
Sector and regulation tags come from keyword matching and are hints, not a compliance assessment.</p>
<h2>Sources</h2>{sources}<h3>Vulnerability data</h3><ul class="plain"><li>CISA Known Exploited Vulnerabilities catalog</li></ul>"""
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
