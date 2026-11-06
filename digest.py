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
import time
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
RETRIES = 1           # extra attempts after a timeout or connection error
RETRY_PAUSE = 5       # seconds between attempts
STALE_DAYS = 30       # a feed whose newest post is older than this is flagged as stale
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
    """Download a source, or read it from the fixtures folder when testing offline.

    Timeouts and connection errors are retried once after a short pause, so one slow
    response doesn't count as a failed source. HTTP errors (403, 404...) are not retried.
    """
    if fixtures:
        path = fixtures / f"{source_id}{suffix}"
        if not path.exists():
            raise FileNotFoundError(f"no fixture file {path.name}")
        return path.read_bytes()
    for attempt in range(1, RETRIES + 2):
        try:
            response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
            response.raise_for_status()
            return response.content
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt > RETRIES:
                raise
            print(f"retrying {source_id} after: {exc}", file=sys.stderr)
            time.sleep(RETRY_PAUSE)
    raise RuntimeError("unreachable")


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
            # Newest post in the feed, even if it's outside the lookback window.
            # This tells a quiet source (newest post 3 days ago) from a dead feed (newest post months ago).
            dates = [t for t in (entry_time(e) for e in parsed.entries) if t]
            if dates:
                status["newest"] = min(max(dates), now).isoformat()
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
# Story grouping: the same story reported by several outlets becomes one entry
# ---------------------------------------------------------------------------

# Words that say little about WHICH story it is (they appear in most security headlines).
STOPWORDS = set("""
a an the and or but for to of in on at by with from into over under about after before via as is are was were be
been being it its this that these those their there here new now just more most than also how why what who when
which says said say warns warn report reports reported according amid against out up down off all any can could
may might will would use used using uses targets target targeting hit hits hackers hacker attackers attacker attack
attacks security cyber cybersecurity vulnerability vulnerabilities flaw flaws bug bugs patch patches patched fix
fixes fixed exploit exploited exploits exploitation update updates critical severe high actively campaign campaigns
threat threats actors actor malicious data million users user companies company firms firm week today year years
""".split())
CVE_IN_TEXT = re.compile(r"cve-\d{4}-\d{4,}", re.I)
GROUP_WINDOW_HOURS = 72   # only group articles published within this many hours of each other
MIN_SHARED_WORDS = 3      # at least this many meaningful words in common...
MIN_SIMILARITY = 0.4      # ...and this much overlap (Jaccard: shared words / all words)


def title_words(title: str) -> set[str]:
    words = set()
    for word in re.findall(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]|[a-z0-9]", title.lower()):
        if word in STOPWORDS or (len(word) < 3 and not word.isdigit()):
            continue
        if len(word) > 4 and word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]  # crude plural folding: "routers" -> "router"
        words.add(word)
    return words


def same_story(a: dict, b: dict) -> bool:
    gap = abs(datetime.fromisoformat(a["published"]) - datetime.fromisoformat(b["published"]))
    if gap > timedelta(hours=GROUP_WINDOW_HOURS):
        return False
    if a["_cves"] & b["_cves"]:
        return True  # the same CVE ID is a strong signal
    shared = a["_words"] & b["_words"]
    union = a["_words"] | b["_words"]
    return len(shared) >= MIN_SHARED_WORDS and len(shared) / len(union) >= MIN_SIMILARITY


def group_stories(items: list[dict], source_order: dict) -> list[dict]:
    """Cluster items that report the same story (union-find), then build one story per cluster.

    The main article is chosen by source order in config.yaml (feeds listed first are preferred).
    Filters work on the story: its tags are the union of all articles' tags.
    """
    for item in items:
        item["_words"] = title_words(item["title"])
        item["_cves"] = {c.upper() for c in CVE_IN_TEXT.findall(item["title"])}
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if find(i) != find(j) and same_story(items[i], items[j]):
                parent[find(j)] = find(i)

    clusters: dict[int, list[dict]] = {}
    for i, item in enumerate(items):
        clusters.setdefault(find(i), []).append(item)

    stories = []
    for members in clusters.values():
        members.sort(key=lambda i: (source_order.get(i["source"], 999), i["published"]))
        main, others = members[0], members[1:]

        def union(key: str) -> list[str]:
            out = []
            for m in members:
                out += [v for v in m.get(key, []) if v not in out]
            return out

        stories.append({
            "main": main,
            "others": sorted(others, key=lambda i: i["published"]),
            "tags": union("tags"), "sectors": union("sectors"), "regulations": union("regulations"),
            "watch": union("watch"),
            "type": main.get("type", "news"),
            "first": min(m["published"] for m in members),
            "latest": max(m["published"] for m in members),
        })
    for item in items:
        item.pop("_words", None)
        item.pop("_cves", None)
    # Newest first, by when the story was first reported (that's the time shown on the card).
    return sorted(stories, key=lambda s: s["first"], reverse=True)


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


def render_filters(cfg: dict, stories: list[dict]) -> str:
    """Filter panel. Hidden until app.js runs, so the page still works without JavaScript."""
    groups_html = []
    for key, cfg_key, label in GROUPS:
        chips = []
        for name in (cfg.get(cfg_key) or {}):
            count = sum(name in s.get(key, []) for s in stories)
            chips.append(f'<button type="button" class="chip{" empty" if not count else ""}" data-group="{"topics" if key == "tags" else key}" '
                         f'data-value="{esc(name)}" aria-pressed="false">{esc(name)} <span class="count">{count}</span></button>')
        groups_html.append(f'<div class="chip-group"><span class="group-label">{esc(label)}</span><div class="chips">{"".join(chips)}</div></div>')
    type_chips = "".join(
        f'<button type="button" class="chip" data-group="types" data-value="{esc(t)}" aria-pressed="false">{esc(label)} '
        f'<span class="count">{sum(s.get("type") == t for s in stories)}</span></button>'
        for t, label in SOURCE_TYPES.items())
    groups_html.append(f'<div class="chip-group"><span class="group-label">Source type</span><div class="chips">{type_chips}</div></div>')

    return f"""<section class="filter-panel" id="filters" hidden aria-label="Filters">
  <div class="filter-row">
    <label for="profile-select" class="group-label">Profile</label>
    <select id="profile-select"></select>
    <input type="search" id="filter-search" placeholder="Search, for example fortinet" aria-label="Search stories">
  </div>
  <div class="filter-row">
    <label class="inline"><input type="checkbox" id="filter-watch"> Watchlist only</label>
    <label class="inline"><input type="checkbox" id="compact-view"> Compact view</label>
    <span class="spacer"></span>
    <button type="button" id="copy-link">Copy link</button>
    <button type="button" id="clear-filters">Clear filters</button>
    <button type="button" id="profile-delete" hidden>Delete profile</button>
  </div>
  <details id="more-filters">
    <summary>Topics, sectors, regulations and source types <span id="active-summary" class="muted"></span></summary>
    <div class="filter-body">
      <span class="inline match" role="radiogroup" aria-label="Match mode">Show stories that match
        <label class="inline"><input type="radio" name="match" value="any" checked> any filter</label>
        <label class="inline"><input type="radio" name="match" value="all"> every group</label>
      </span>
      {"".join(groups_html)}
      <div class="filter-row">
        <input type="text" id="profile-name" maxlength="60" placeholder="Name this filter set, for example Healthcare SOC" aria-label="Profile name">
        <button type="button" id="profile-save">Save as profile</button>
      </div>
      <p class="hint">Saved profiles are stored in this browser only. Use "Copy link" to open the same filters on another device.
      Sector and regulation tags are keyword-based hints, not a compliance assessment.</p>
    </div>
  </details>
  <span id="profile-msg" class="msg" role="status"></span>
</section>
<p id="filter-status" class="muted" role="status"></p>"""


def render_story(story: dict, tz: ZoneInfo) -> str:
    main = story["main"]
    others = story["others"]
    badges = ("".join(badge(t) for t in story["tags"])
              + "".join(badge(s, "sector") for s in story["sectors"])
              + "".join(badge(r, "reg") for r in story["regulations"])
              + "".join(badge(w, "watch") for w in story["watch"]))
    everything = [main] + others
    attrs = {
        "data-topics": "|".join(story["tags"]),
        "data-sectors": "|".join(story["sectors"]),
        "data-regulations": "|".join(story["regulations"]),
        "data-type": story["type"],
        "data-watch": "1" if story["watch"] else "0",
        "data-search": " ".join(f"{i['title']} {i['source']}" for i in everything).lower(),
        "data-published": story["latest"],
    }
    attr_html = " ".join(f'{k}="{esc(v)}"' for k, v in attrs.items())
    type_label = SOURCE_TYPES.get(story["type"], "News")
    classes = "card item" + (" watched" if story["watch"] else "") + (" grouped" if others else "")
    sources_badge = f'<span class="sources-count">{len(everything)} sources</span>' if others else ""
    also = ""
    if others:
        links = " · ".join(f'<a href="{esc(o["link"])}" rel="noopener noreferrer" title="{esc(o["title"])}">{esc(o["source"])}</a>'
                           for o in others)
        also = f'<div class="also">Also covered by {links}</div>'
    return f"""<li class="{classes}" {attr_html}>
  <a class="title" href="{esc(main['link'])}" rel="noopener noreferrer">{esc(main['title'])}</a>
  <div class="meta">{esc(main['source'])} · {esc(type_label)} · {esc(fmt_time(story['first'], tz))} {sources_badge}</div>
  {also}
  <div class="badges">{badges}</div>
</li>"""


def render_story_list(list_id: str, stories: list[dict], tz: ZoneInfo, day_separators: bool) -> str:
    rows, current_day = [], None
    for story in stories:
        day = datetime.fromisoformat(story["first"]).astimezone(tz).date()
        if day_separators and day != current_day:
            label = day.strftime("%A, %B %d").replace(" 0", " ")
            rows.append(f'<li class="day-sep" aria-hidden="true">{esc(label)}</li>')
            current_day = day
        rows.append(render_story(story, tz))
    return (f'<ul class="list" id="{list_id}">{"".join(rows)}</ul>'
            f'<p class="muted empty-msg" data-for="{list_id}" hidden>No stories match these filters.</p>')


def render_health(health: list[dict], now: datetime, tz: ZoneInfo) -> str:
    rows, problems = [], 0
    for h in health:
        detail = ""
        if h["status"] != "ok":
            state, detail = badge("error", "danger"), esc(h.get("error", ""))
            problems += 1
        else:
            state = badge("ok", "ok")
            detail = f'{h["items"]} new'
            if h.get("newest"):
                newest = datetime.fromisoformat(h["newest"])
                detail += f' · newest post {newest.astimezone(tz).strftime("%b %d").replace(" 0", " ")}'
                if now - newest > timedelta(days=STALE_DAYS):
                    state = badge("stale", "watch")
                    problems += 1
            elif "catalog_version" in h:
                detail += f' · catalog {esc(h["catalog_version"])}'
        rows.append(f"<tr><td>{esc(h['name'])}</td><td>{state}</td><td class=\"muted\">{detail}</td></tr>")
    if not rows:
        return ""
    summary = f"Source status · {len(health) - problems} of {len(health)} healthy"
    return (f'<details class="health"><summary>{esc(summary)}</summary><table>{"".join(rows)}</table>'
            f'<p class="hint">"Stale" means the newest post in a feed is more than {STALE_DAYS} days old: the feed address may have changed.</p></details>')


def render_listing(cfg: dict, heading: str, subtitle: str, items: list[dict], kev: list[dict],
                   health: list[dict], tz: ZoneInfo, generated_at: str | None, multi_day: bool) -> str:
    kev_days = cfg.get("kev_days", 7)
    order = {f["name"]: n for n, f in enumerate(cfg.get("feeds", []))}
    research = group_stories([i for i in items if i.get("type") == "research"], order)
    headlines = group_stories([i for i in items if i.get("type") != "research"], order)
    stories = headlines + research
    watch_count = sum(bool(s["watch"]) for s in stories) + sum(bool(v.get("watch")) for v in kev)
    articles = len(items)

    parts = [f"<h1>{esc(heading)}</h1>"]
    if subtitle:
        parts.append(f'<p class="muted">{esc(subtitle)} <span id="new-since"></span></p>')
    parts.append(f"""<section class="stats">
  <div class="stat"><span>Stories</span><strong>{len(headlines)}</strong><small>{articles} articles</small></div>
  <div class="stat"><span>Research reports</span><strong>{len(research)}</strong></div>
  <div class="stat"><span>Newly exploited (KEV)</span><strong class="danger">{len(kev)}</strong><small>last {kev_days} days</small></div>
  <div class="stat"><span>Watchlist hits</span><strong class="warning">{watch_count}</strong></div>
</section>""")

    # Actively exploited vulnerabilities: first 3 visible, the rest behind "show more"
    parts.append(f'<h2>Actively exploited <span class="h-count">{len(kev)}</span></h2>')
    if kev:
        def kev_card(v: dict) -> str:
            flags = "".join(badge(w, "watch") for w in v["watch"])
            if v["ransomware"]:
                flags += badge("used in ransomware", "danger")
            nvd = f"https://nvd.nist.gov/vuln/detail/{v['cve']}"
            search = f"{v['cve']} {v['vendor']} {v['product']} {v['name']}".lower()
            return f"""<li class="card kev{' watched' if v['watch'] else ''}" data-watch="{'1' if v['watch'] else '0'}" data-search="{esc(search)}">
  <div class="row"><a class="mono" href="{esc(nvd)}" rel="noopener noreferrer">{esc(v['cve'])}</a>
  <span class="muted">added {esc(v['added'])} · fix by {esc(v['due'])}</span></div>
  <div class="title">{esc(v['name'] or f"{v['vendor']} {v['product']}")}</div>
  <p class="desc">{esc(v['description'])}</p>
  <div class="badges">{flags}</div>
</li>"""
        ordered = sorted(kev, key=lambda v: not v["watch"])  # watchlist matches first
        parts.append(f'<p class="muted">From the CISA Known Exploited Vulnerabilities catalog, added in the last {kev_days} days.</p>')
        parts.append(f'<ul class="list" id="kev-list">{"".join(kev_card(v) for v in ordered[:3])}</ul>')
        if len(ordered) > 3:
            parts.append(f'<details class="more"><summary>Show {len(ordered) - 3} more</summary>'
                         f'<ul class="list">{"".join(kev_card(v) for v in ordered[3:])}</ul></details>')
    else:
        parts.append('<p class="muted">No new KEV entries in this period.</p>')

    parts.append(render_filters(cfg, stories))

    for list_id, title, group in (("headlines", "Headlines", headlines), ("research", "Threat research", research)):
        parts.append(f'<h2>{title} <span class="h-count">{len(group)}</span></h2>')
        if group:
            parts.append(render_story_list(list_id, group, tz, day_separators=multi_day))
        else:
            parts.append(f'<p class="muted">No {title.lower()} in this period.</p>')

    now = datetime.fromisoformat(generated_at) if generated_at else datetime.now(timezone.utc)
    parts.append(render_health(health, now, tz))
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
        home = render_listing(cfg, day_heading(d), updated(d), d["items"], d.get("kev", []), d.get("health", []), tz,
                              d.get("generated_at"), multi_day=False)
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
                              recent[0].get("kev", []), recent[0].get("health", []), tz,
                              recent[0].get("generated_at"), multi_day=True)
    else:
        body = "<h1>No data yet</h1>"
    write("recent.html", page(cfg, f"Last {recent_n} days", body, profiles=profiles))

    # Archive: one page per day
    links = []
    for day in days:
        body = render_listing(cfg, day_heading(day), updated(day), day["items"], day.get("kev", []), day.get("health", []), tz,
                              day.get("generated_at"), multi_day=False)
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
groups the same story from different outlets into one entry, tags items by topic, sector and regulation,
highlights technology on my watchlist and rebuilds this site.
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
