# Translating fxcloud

Every user-facing string of the UI lives in one file:
`frontend/assets/i18n.js`. It holds the engine *and* the dictionaries, so a
language switch costs zero round trips and the pages can never render
half-translated while a second asset loads. There is no i18n framework and
no template step - plain strings in, DOM text out.

Current languages, in switcher order:

| code | language         | note                                   |
|------|------------------|----------------------------------------|
| de   | German           | first flag in the switcher             |
| en   | English          | default, source text, fallback          |
| tlh  | Klingon          | third flag; proof the engine is N-ready |

English is the default on purpose: without a stored choice the UI starts on
English and never sniffs the browser language. Whoever wants another
language picks the flag once; the choice sticks in
`localStorage["fxcloud.lang"]`.

## What a new language needs

Five pieces, all in `frontend/assets/i18n.js`:

1. **A dictionary.** Copy the `EN` object (`var XX = { ... };`) and
   translate every key. The English value is the source; the key never
   changes. Keep the section comments - they mirror the UI's structure.

2. **Registration.** Add the object to the catalogue and the code to the
   order (flag order is `CODES` order, English stays the default):

   ```js
   var LANGS = { de: DE, en: EN, tlh: TLH, xx: XX };
   var CODES = ["de", "en", "tlh", "xx"];
   ```

3. **A flag** in `flag(code)`: a tiny inline SVG, deliberately not an emoji
   (Windows renders regional-indicator pairs as the letters "DE"/"GB"
   instead of a flag). ~18x11 pixels, self-explanatory at a glance.

4. **An endonym** in the `ENDONYMS` map: the language's own name for
   itself, shown as the button's title and aria-label.

5. **Optionally a locale** in `LOCALES` for dates and numbers
   (`Intl` tag like `de-DE`). Languages without one fall back to the
   browser's own formatting.

The switcher needs no further work: `renderSwitch()` draws a dropdown
into every `.lang-switch` container (topbar, settings dialog, login
card) - a button with the current flag opens a menu with one row per
`CODES` entry (flag plus endonym) - and repaints all of them on a
switch.

## Rules for strings

- **Pure ASCII in the file.** Letters like umlauts are spelled with
  escapes; the browser decodes them. Cheat sheet:

  ```
  a=\u00e4  o=\u00f6  u=\u00fc  s=\u00df          A=\u00c4 O=\u00d6 U=\u00dc
  e=\u00e9  e=\u00e8  e=\u00ea  c=\u00e7          etc.
  ```

  The suite fails on any non-ASCII byte, so this cannot rot.

- **Placeholders stay verbatim.** `{name}`, `{n}`, `{used}`, `{quota}`,
  `{msg}`, ... - same spelling, any position. The code replaces them with
  `t("key", { name: ... })`.

- **Keys are stable API.** `app.js`, `fxenc.js`, `login.js` and both HTML
  pages refer to them; renaming a key means touching every call site. The
  suite cross-checks all of them against every dictionary.

- **English in the static HTML stays.** It is the fallback for no-JS
  readers and for a key a dictionary has not covered yet. Mark elements
  with `data-i18n="key"` (textContent), `data-i18n-ph` (placeholder),
  `data-i18n-title` (title) or `data-i18n-aria` (aria-label).

- **Dynamic strings call `t()`.** Anything built in JS uses
  `t("key", params)`. When the language changes, re-render from data and
  listen for the `fxcloud:langchange` event on `document` - see the
  listeners at the end of `app.js` and in `fxenc.js`. Never cache a
  translated string across a language switch.

- **Server errors translate too.** The API answers with a stable `code`
  beside the English text (`src/error.rs`); batch failures carry one per
  item. The UI maps them to `err.<code>` keys, so a new language only
  needs those dictionary entries - no server change.

## How the keys are organized

The `EN` dictionary is cut into the same sections the UI uses, in UI
order: topbar, toolbar, dropzone, table headers, bulk action bar, shared
verbs, rows, empty states, share dialog, move/copy dialog, prompts,
confirms and batch reports, upload/preview/editor, settings dialog,
passkeys, admin table and reset dialog, encryption panes, encryption
runtime strings, the login/register page, server error codes, permission
names. A section header comment marks each group in all dictionaries.

## Testing a translation

`tests/suite.sh` pins the whole layer (it is part of the 400+ checks):

- every dictionary in `CODES` has the exact key set of `EN` (parity walk -
  a missing key fails by name);
- every `t("...")` call site in JS and every `data-i18n*` mark in the
  HTML resolves in every language;
- English is the default, the switcher order is pinned, each offered
  language draws its own flag;
- the UI never sniffs the browser language, and the choice persists in
  `localStorage`;
- `i18n.js` stays pure ASCII.

Run it with:

```
NODE=$(command -v node) ./tests/suite.sh
```

The i18n section prints which key or language broke, so a fresh
translation usually needs one suite run to shake out typos in key names.

## A note on Klingon

Klingon (`tlh`) has no `Intl` locale, so dates use the browser's own
formatting (`LOCALES` has no entry). The strings use canonical vocabulary
where the language has a word (`juH` home, `poS` open, `qaw` forget,
`yuD` download, `laD` load, `quj` key) and consistent compounds where it
does not (`bIQroq` folder, `quj pon` fingerprint). New tlh strings should
follow the same rule and stay short: this is an interface, not a poem.
