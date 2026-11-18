#!/usr/bin/env node
/*
 * Help page generator: USERGUIDE.md (+ its translations) -> static HTML.
 *
 *   node frontend/tests/gen-help.js          # (re)write the pages
 *   node frontend/tests/gen-help.js --check  # verify them (suite/CI)
 *
 * The guide is the source of truth; the pages under frontend/assets are
 * build products of it, exactly like the icons. The markdown subset is
 * what the guide actually uses - headings with anchors, lists, task
 * lists, fenced code, bold, inline code, links - converted with every
 * text node escaped first, so no guide text can become markup. Relative
 * links point into the repository (README.md etc.); from /help they
 * would404, so they are rewritten to the GitHub blob view. Anchor links
 * stay as they are: the slug rule here (lowercase, accents stripped,
 * punctuation dropped, spaces to hyphens) is what produced them in the
 * table of contents of each file.
 */
"use strict";

const path = require("path");
const fs = require("fs");

const REPO = path.join(__dirname, "..", "..");
const OUT_DIR = path.join(REPO, "frontend", "assets");

const LANGS = [
  { code: "en", source: "USERGUIDE.md", out: "help-en.html", label: "English" },
  { code: "de", source: "USERGUIDE.de.md", out: "help-de.html", label: "Deutsch" },
  { code: "tlh", source: "USERGUIDE.tlh.md", out: "help-tlh.html", label: "tlhIngan Hol" },
];

// Chrome around the guide: the language switcher is plain links (no JS,
// CSP-safe), the back link returns to the app. The footer badge slot is
// filled server-side, like on every other page.
const CHROME = {
  en: { back: "Back to fxcloud", lang: "Language" },
  de: { back: "Zurück zu fxcloud", lang: "Sprache" },
  tlh: { back: "fxcloud poS", lang: "Hol" },
};

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** The anchor rule, applied to a heading's visible text. */
function slug(text) {
  return (
    text
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "") // accents: u for ü, etc.
      .replace(/[^a-z0-9 -]/g, "") // punctuation (incl. apostrophes) goes
      .trim()
      .replace(/ +/g, "-")
  );
}

/** Inline markdown: code, bold, links - the text is escaped as we go. */
function inline(src) {
  let out = "";
  let i = 0;
  while (i < src.length) {
    if (src[i] === "`") {
      const end = src.indexOf("`", i + 1);
      if (end > i) {
        out += "<code>" + esc(src.slice(i + 1, end)) + "</code>";
        i = end + 1;
        continue;
      }
    }
    if (src.startsWith("**", i)) {
      const end = src.indexOf("**", i + 2);
      if (end > i) {
        out += "<strong>" + inline(src.slice(i + 2, end)) + "</strong>";
        i = end + 2;
        continue;
      }
    }
    if (src[i] === "[") {
      const close = src.indexOf("]", i);
      if (close > i && src[close + 1] === "(") {
        const paren = src.indexOf(")", close + 1);
        if (paren > close) {
          const text = inline(src.slice(i + 1, close));
          const href = link(src.slice(close + 2, paren));
          out += '<a href="' + href + '">' + text + "</a>";
          i = paren + 1;
          continue;
        }
      }
    }
    out += esc(src[i]);
    i += 1;
  }
  return out;
}

/** Repo-relative links become GitHub blob links; anchors and http(s) stay. */
function link(href) {
  if (href.startsWith("#") || href.startsWith("http://") || href.startsWith("https://")) {
    return href;
  }
  return "https://github.com/floyd54/fxcloud/blob/main/" + href;
}

/** Markdown -> body HTML for the guide's subset. */
function markdown(src) {
  const lines = src.split(/\r?\n/);
  const out = [];
  let i = 0;
  let para = [];

  const flush = () => {
    if (para.length) {
      out.push("<p>" + inline(para.join(" ")) + "</p>");
      para = [];
    }
  };

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code: verbatim, escaped, no markdown inside.
    if (line.startsWith("```")) {
      flush();
      const lang = line.slice(3).trim();
      const body = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1; // closing fence (or EOF)
      const cls = lang ? ' class="language-' + esc(lang) + '"' : "";
      out.push("<pre><code" + cls + ">" + esc(body.join("\n")) + "\n</code></pre>");
      continue;
    }

    // Headings carry the anchor the table of contents links to.
    const h = /^(#{1,3}) (.*)$/.exec(line);
    if (h) {
      flush();
      const level = h[1].length;
      const text = h[2].trim();
      out.push(
        "<h" + level + ' id="' + esc(slug(text)) + '">' + inline(text) + "</h" + level + ">"
      );
      i += 1;
      continue;
    }

    // Ordered list.
    if (/^\d+\. /.test(line)) {
      flush();
      const items = [];
      while (i < lines.length && /^\d+\. /.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\. /, ""));
        i += 1;
      }
      out.push("<ol>" + items.map((t) => "<li>" + inline(t) + "</li>").join("") + "</ol>");
      continue;
    }

    // Task list / bullet list (one level; the guide has no nesting).
    if (/^- \[[ x]\] /.test(line) || /^- /.test(line)) {
      flush();
      const items = [];
      let task = false;
      while (i < lines.length && (/^- \[[ x]\] /.test(lines[i]) || /^- /.test(lines[i]))) {
        const m = /^- \[([ x])\] (.*)$/.exec(lines[i]);
        if (m) {
          task = true;
          items.push('<li class="task">' + (m[1] === "x" ? "[x] " : "[ ] ") + inline(m[2]) + "</li>");
        } else {
          items.push("<li>" + inline(lines[i].slice(2)) + "</li>");
        }
        i += 1;
      }
      out.push(
        (task ? '<ul class="tasks">' : "<ul>") + items.join("") + "</ul>"
      );
      continue;
    }

    // Blank line ends a paragraph.
    if (line.trim() === "") {
      flush();
      i += 1;
      continue;
    }

    para.push(line.trim());
    i += 1;
  }
  flush();
  return out.join("\n");
}

/** The full page: chrome + converted guide, one file per language. */
function page(lang, body) {
  const chrome = CHROME[lang.code];
  const links = LANGS.map(
    (l) =>
      '<a class="lang' +
      (l.code === lang.code ? " active" : "") +
      '" href="/help?lang=' +
      l.code +
      '">' +
      esc(l.label) +
      "</a>"
  ).join(" · ");
  const switchLabel = esc(chrome.lang);
  return `<!DOCTYPE html>
<html lang="${lang.code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fxcloud - ${switchLabel === "Sprache" ? "Hilfe" : switchLabel === "Hol" ? "paq" : "Help"}</title>
<link rel="stylesheet" href="/assets/style.css">
<style>
  body.help { max-width: 46rem; margin: 0 auto; padding: 1rem 1.25rem 4rem; line-height: 1.6; }
  body.help header { display: flex; justify-content: space-between; align-items: center;
    gap: 1rem; flex-wrap: wrap; padding: .75rem 0; border-bottom: 1px solid var(--border, #ccc); }
  body.help header a { text-decoration: none; }
  body.help .langs { font-size: .9rem; opacity: .85; }
  body.help .langs a.active { font-weight: bold; text-decoration: none; }
  body.help h1 { font-size: 1.6rem; margin: 1.5rem 0 .5rem; }
  body.help h2 { font-size: 1.25rem; margin: 2rem 0 .5rem; padding-top: .75rem;
    border-top: 1px solid var(--border, #ccc); }
  body.help h3 { font-size: 1.05rem; margin: 1.4rem 0 .4rem; }
  body.help pre { background: var(--code-bg, #f4f4f4); padding: .75rem; overflow-x: auto;
    border-radius: .35rem; font-size: .85rem; }
  body.help code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .9em; background: var(--code-bg, #f4f4f4); padding:0 .25em; border-radius: .25em; }
  body.help pre code { background: none; padding: 0; }
  body.help ul, body.help ol { padding-left: 1.4rem; }
  body.help li { margin: .25rem 0; }
  body.help a { color: inherit; }
  body.help footer { margin-top: 3rem; font-size: .8rem; opacity: .7; }
</style>
</head>
<body class="help">
<header>
  <a href="/">${esc(chrome.back)}</a>
  <nav class="langs" aria-label="${switchLabel}">${links}</nav>
</header>
<main>
${body}
</main>
<footer>fxcloud {{version}}</footer>
</body>
</html>
`;
}

function build(lang) {
  const src = fs.readFileSync(path.join(REPO, lang.source), "utf8");
  return page(lang, markdown(src));
}

function main() {
  const check = process.argv.includes("--check");
  let bad = 0;
  for (const lang of LANGS) {
    const html = build(lang);
    const out = path.join(OUT_DIR, lang.out);
    if (check) {
      let have = null;
      try {
        have = fs.readFileSync(out, "utf8");
      } catch (_) {
        /* missing counts as drift */
      }
      if (have !== html) {
        console.log("FAIL " + lang.out + " drifted from " + lang.source);
        bad += 1;
      }
    } else {
      fs.writeFileSync(out, html);
      console.log("wrote " + lang.out + " (" + html.length + " bytes)");
    }
  }
  if (check) {
    if (bad) process.exit(1);
    console.log("help pages match the guides (" + LANGS.length + " languages)");
  }
}

main();
