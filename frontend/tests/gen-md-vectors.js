// Generates tests/fixtures/md-vectors.json from the web's own
// renderer: the app's Markdown.toHtml is a Kotlin port of the
// function below, and this script pins the two together - change
// mdToHtml in app.js without regenerating and the JVM vector test
// fails, change the port without regenerating and it fails too.
//
//   node frontend/tests/gen-md-vectors.js
const fs = require("fs");
const path = require("path");

const appJs = fs.readFileSync(
  path.join(__dirname, "..", "assets", "app.js"),
  "utf8"
);
const start = appJs.indexOf("function mdToHtml");
if (start < 0) throw new Error("mdToHtml not found in app.js");
// The function is self-contained (esc/safeUrl/inline are its own
// consts) and closes at the two-space indent of its declaration.
const end = appJs.indexOf("\n  }", start);
if (end < 0) throw new Error("mdToHtml end not found");
const mdToHtml = eval(`(${appJs.slice(start, end + 4)})`);

const cases = [
  "",
  "Hello world",
  "line one\nline two",
  "para1\r\n\r\npara2\r\n",
  "# Title\n## Sub\n\nbody",
  "---\n***\n___",
  "some **bold** and *em* and ~~gone~~ text",
  "code `**not bold**` here",
  "[link](https://x.test/a) and [bad](javascript:alert(1)) and " +
    "[rel](/local) and [hash](#top)",
  "![img](https://x.test/i.png) ![bad](javascript:x) ![alt](data:text/html,x)",
  "- one\n- two\n1. first\n2. second",
  "> quoted\n> lines\n\nafter",
  "```js\n# not a heading\n**no**\n```",
  "unclosed ```\nstill code",
  "<script>alert(1)</script> & \"quotes\" <b>bold</b>",
  "code with entities: `a & b < c`",
  "   indented para\n\ttab para",
  "- [ ] task list item",
  "## Heading\n- list right after heading",
  "text with trailing spaces   \nnext line"
];

const out = cases.map((input) => ({ input, html: mdToHtml(input) }));
const target = path.join(__dirname, "..", "..", "tests", "fixtures", "md-vectors.json");
fs.writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${out.length} vectors to ${target}`);
