// Filters, profiles and "new since last visit" for the threat digest.
// The pages work without JavaScript; this only adds filtering on top.
(function () {
  "use strict";

  var GROUPS = ["topics", "sectors", "regulations", "types"];
  var KEY_PROFILES = "td-profiles";   // custom profiles saved in this browser
  var KEY_LAST = "td-last-profile";   // profile to re-apply on the next visit
  var KEY_VISIT = "td-last-visit";    // time of the previous visit
  var KEY_COMPACT = "td-compact";     // compact view on/off

  // localStorage can be unavailable (private mode, blocked storage), so every access is wrapped.
  function load(key, fallback) {
    try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; }
  }
  function store(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch (e) { return false; }
  }
  function $(id) { return document.getElementById(id); }
  function split(value) { return value ? value.split("|") : []; }

  // ---- "New since your last visit" -------------------------------------------------
  var lastVisit = load(KEY_VISIT, null);
  store(KEY_VISIT, new Date().toISOString());
  var newCount = 0;
  if (lastVisit) {
    document.querySelectorAll(".card.item").forEach(function (card) {
      if (card.getAttribute("data-published") > lastVisit) {
        var span = document.createElement("span");
        span.className = "badge new";
        span.textContent = "new";
        card.querySelector(".badges").prepend(span);
        newCount++;
      }
    });
    var note = $("new-since");
    if (note && newCount) note.textContent = "· " + newCount + " new since your last visit";
  }

  // ---- Compact view (headlines only) -----------------------------------------------
  var compact = $("compact-view");
  if (load(KEY_COMPACT, false) === true) document.body.classList.add("compact");
  if (compact) {
    compact.checked = document.body.classList.contains("compact");
    compact.addEventListener("change", function () {
      document.body.classList.toggle("compact", compact.checked);
      store(KEY_COMPACT, compact.checked);
    });
  }

  // ---- Filters ---------------------------------------------------------------------
  var panel = $("filters");
  if (!panel) return;
  panel.hidden = false;

  var presets = [];
  try { presets = JSON.parse(($("profiles-data") || {}).textContent || "[]"); } catch (e) { presets = []; }

  function emptyState() {
    return { topics: [], sectors: [], regulations: [], types: [], match: "any", watch: false, q: "" };
  }
  function normalize(raw) {
    var s = emptyState();
    if (!raw || typeof raw !== "object") return s;
    GROUPS.forEach(function (g) {
      s[g] = Array.isArray(raw[g]) ? raw[g].filter(function (v) { return typeof v === "string"; }) : [];
    });
    s.match = raw.match === "all" ? "all" : "any";
    s.watch = raw.watch === true;
    s.q = typeof raw.q === "string" ? raw.q.slice(0, 100) : "";
    return s;
  }
  function sameState(a, b) {
    return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
  }

  var state = emptyState();
  var current = "";            // selected profile key: "", "preset:<i>" or "custom:<name>"

  var select = $("profile-select");
  var search = $("filter-search");
  var watch = $("filter-watch");
  var msg = $("profile-msg");
  var nameInput = $("profile-name");
  var chips = panel.querySelectorAll(".chip");
  var items = document.querySelectorAll(".card.item");
  var kevCards = document.querySelectorAll(".card.kev");

  function customProfiles() {
    var list = load(KEY_PROFILES, []);
    return Array.isArray(list) ? list.filter(function (p) { return p && typeof p.name === "string"; }) : [];
  }

  function profileFor(key) {
    if (key.indexOf("preset:") === 0) return presets[Number(key.slice(7))] || null;
    if (key.indexOf("custom:") === 0) {
      var name = key.slice(7);
      return customProfiles().filter(function (p) { return p.name === name; })[0] || null;
    }
    return null;
  }

  function option(value, text) {
    var o = document.createElement("option");
    o.value = value;
    o.textContent = text;
    return o;
  }

  function renderSelect() {
    select.textContent = "";
    select.appendChild(option("", "All items (no profile)"));
    if (presets.length) {
      var g1 = document.createElement("optgroup");
      g1.label = "Preset profiles";
      presets.forEach(function (p, i) { g1.appendChild(option("preset:" + i, p.name)); });
      select.appendChild(g1);
    }
    var mine = customProfiles();
    if (mine.length) {
      var g2 = document.createElement("optgroup");
      g2.label = "My profiles";
      mine.forEach(function (p) { g2.appendChild(option("custom:" + p.name, p.name)); });
      select.appendChild(g2);
    }
    select.appendChild(option("edited", "Unsaved filters"));
  }

  function matches(card) {
    var data = {
      topics: split(card.getAttribute("data-topics")),
      sectors: split(card.getAttribute("data-sectors")),
      regulations: split(card.getAttribute("data-regulations")),
      types: [card.getAttribute("data-type")]
    };
    var active = GROUPS.filter(function (g) { return state[g].length; });
    var ok = true;
    if (active.length) {
      var hits = active.map(function (g) {
        return state[g].some(function (v) { return data[g].indexOf(v) !== -1; });
      });
      ok = state.match === "all" ? hits.every(Boolean) : hits.some(Boolean);
    }
    return ok && basicMatch(card);
  }

  // Search and watchlist also apply to the KEV list; topic chips don't (KEV entries have no topics).
  function basicMatch(card) {
    if (state.watch && card.getAttribute("data-watch") !== "1") return false;
    var q = state.q.trim().toLowerCase();
    return !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
  }

  function apply() {
    var shown = 0;
    items.forEach(function (card) {
      var ok = matches(card);
      card.hidden = !ok;
      if (ok) shown++;
    });
    kevCards.forEach(function (card) { card.hidden = !basicMatch(card); });

    // Hide a day separator when none of the stories under it are visible.
    document.querySelectorAll(".day-sep").forEach(function (sep) {
      var el = sep.nextElementSibling, any = false;
      while (el && !el.classList.contains("day-sep")) {
        if (!el.hidden) { any = true; break; }
        el = el.nextElementSibling;
      }
      sep.hidden = !any;
    });

    document.querySelectorAll(".empty-msg").forEach(function (p) {
      var list = $(p.getAttribute("data-for"));
      p.hidden = !list || list.querySelector(".card:not([hidden])") !== null;
    });

    chips.forEach(function (chip) {
      var on = state[chip.getAttribute("data-group")].indexOf(chip.getAttribute("data-value")) !== -1;
      chip.setAttribute("aria-pressed", on ? "true" : "false");
    });
    search.value = state.q;
    watch.checked = state.watch;
    panel.querySelectorAll('input[name="match"]').forEach(function (r) { r.checked = r.value === state.match; });

    var profile = profileFor(current);
    if (current && current !== "edited" && profile && !sameState(profile, state)) current = "edited";
    select.querySelector('option[value="edited"]').hidden = current !== "edited";
    select.value = current;
    $("profile-delete").hidden = current.indexOf("custom:") !== 0;

    var active = [];
    GROUPS.forEach(function (g) { active = active.concat(state[g]); });
    var summary = active.length ? active.join(", ") + (active.length > 1 ? " (" + (state.match === "all" ? "every group" : "any") + ")" : "") : "";
    $("active-summary").textContent = summary ? "· " + summary : "";

    var status = $("filter-status");
    var filtered = shown !== items.length;
    status.textContent = filtered ? "Showing " + shown + " of " + items.length + " stories" : "";

    // Keep the URL shareable: the current filters live in the address bar.
    var isEmpty = sameState(state, emptyState());
    var hash = isEmpty ? "" : "#f=" + encodeURIComponent(JSON.stringify(state));
    try { history.replaceState(null, "", location.pathname + location.search + hash); } catch (e) { /* ignore */ }
    store(KEY_LAST, current.indexOf("edited") === 0 ? null : current);
  }

  function setMessage(text, isError) {
    msg.textContent = text;
    msg.className = "msg" + (isError ? " error" : "");
  }

  function useProfile(key) {
    var profile = profileFor(key);
    current = profile ? key : "";
    state = profile ? normalize(profile) : emptyState();
    setMessage("");
    apply();
  }

  // ---- Events ----------------------------------------------------------------------
  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      var list = state[chip.getAttribute("data-group")];
      var value = chip.getAttribute("data-value");
      var at = list.indexOf(value);
      if (at === -1) list.push(value); else list.splice(at, 1);
      if (!current) current = "edited";
      apply();
    });
  });

  search.addEventListener("input", function () { state.q = search.value; if (!current) current = "edited"; apply(); });
  watch.addEventListener("change", function () { state.watch = watch.checked; if (!current) current = "edited"; apply(); });
  panel.querySelectorAll('input[name="match"]').forEach(function (r) {
    r.addEventListener("change", function () { state.match = r.value; if (!current) current = "edited"; apply(); });
  });

  select.addEventListener("change", function () {
    if (select.value === "edited") { select.value = current; return; }
    useProfile(select.value);
  });

  $("clear-filters").addEventListener("click", function () { useProfile(""); });

  $("profile-save").addEventListener("click", function () {
    var name = nameInput.value.trim();
    if (!name) { setMessage("Enter a name first.", true); nameInput.focus(); return; }
    if (sameState(state, emptyState())) { setMessage("Select at least one filter first.", true); return; }
    var mine = customProfiles().filter(function (p) { return p.name !== name; });
    var saved = normalize(state);
    saved.name = name;
    mine.push(saved);
    if (!store(KEY_PROFILES, mine)) { setMessage("Couldn't save: browser storage is unavailable.", true); return; }
    current = "custom:" + name;
    renderSelect();
    nameInput.value = "";
    setMessage("Saved “" + name + "”.");
    apply();
  });
  nameInput.addEventListener("input", function () { if (msg.className.indexOf("error") !== -1) setMessage(""); });

  $("profile-delete").addEventListener("click", function () {
    if (current.indexOf("custom:") !== 0) return;
    var name = current.slice(7);
    store(KEY_PROFILES, customProfiles().filter(function (p) { return p.name !== name; }));
    renderSelect();
    setMessage("Deleted “" + name + "”.");
    current = "edited";
    apply();
  });

  $("copy-link").addEventListener("click", function () {
    var url = location.href;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(
        function () { setMessage("Link copied."); },
        function () { setMessage("Copy this link from the address bar."); });
    } else {
      setMessage("Copy this link from the address bar.");
    }
  });

  // ---- Start: filters from the link first, otherwise the last used profile ----------
  function stateFromHash() {
    if (location.hash.indexOf("#f=") !== 0) return null;
    try { return normalize(JSON.parse(decodeURIComponent(location.hash.slice(3)))); } catch (e) { return null; }
  }
  window.addEventListener("hashchange", function () {
    var s = stateFromHash();
    if (s) { state = s; current = "edited"; apply(); }
  });

  renderSelect();
  var fromHash = stateFromHash();
  if (fromHash) {
    state = fromHash;
    current = "edited";
    apply();
  } else {
    var last = load(KEY_LAST, null);
    useProfile(typeof last === "string" && profileFor(last) ? last : "");
  }
})();
