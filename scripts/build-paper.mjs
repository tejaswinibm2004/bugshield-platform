/**
 * Renders paper2.md to paper2.pdf using an IEEE-style two-column layout.
 * Markdown -> HTML (marked) -> HTML with print CSS -> PDF (headless Chromium).
 *
 * Usage:  node scripts/build-paper.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'url';
import { marked } from 'marked';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'paper2.md');
const HTML = path.join(ROOT, 'paper2.html');
const PDF = path.join(ROOT, 'paper2.pdf');

const BROWSERS = [
  `${process.env.ProgramFiles}\\Google\\Chrome\\Application\\chrome.exe`,
  `${process.env['ProgramFiles(x86)']}\\Microsoft\\Edge\\Application\\msedge.exe`,
  `${process.env.ProgramFiles}\\Microsoft\\Edge\\Application\\msedge.exe`
];
const browser = BROWSERS.find(p => p && fs.existsSync(p));
if (!browser) { console.error('No Chromium browser found for PDF rendering.'); process.exit(1); }

const md = fs.readFileSync(SRC, 'utf-8');
const body = marked.parse(md, { gfm: true, breaks: false });

// Journal-style: serif body, two columns, justified, running header/footer.
const css = `
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
* { box-sizing: border-box; }
body {
  font-family: "Times New Roman", Times, serif;
  font-size: 9.6pt; line-height: 1.32; color: #111; margin: 0;
  column-count: 2; column-gap: 7mm; text-align: justify; hyphens: auto;
}
h1 { font-size: 17pt; line-height: 1.15; text-align: center; margin: 0 0 6pt; column-span: all; font-weight: 700; }
h2 { font-size: 10.5pt; margin: 12pt 0 4pt; column-span: all; text-transform: uppercase; letter-spacing: .3pt; border-bottom: 1px solid #333; padding-bottom: 2pt; }
h3 { font-size: 10pt; margin: 9pt 0 3pt; font-weight: 700; }
h4 { font-size: 9.8pt; margin: 7pt 0 2pt; font-style: italic; }
p { margin: 0 0 5pt; }
ul, ol { margin: 0 0 6pt; padding-left: 15pt; }
li { margin-bottom: 2pt; }
code { font-family: "Consolas", monospace; font-size: 8.4pt; background: #f2f2f2; padding: 0 2px; border-radius: 2px; }
pre { font-family: "Consolas", monospace; font-size: 8pt; background: #f5f5f5; border: 1px solid #ddd; border-left: 3px solid #888; padding: 5pt 7pt; white-space: pre-wrap; word-break: break-word; column-span: all; margin: 6pt 0; }
table { border-collapse: collapse; width: 100%; font-size: 8.4pt; margin: 6pt 0; column-span: all; }
th, td { border: 1px solid #999; padding: 3pt 4pt; text-align: left; vertical-align: top; }
th { background: #ececec; font-weight: 700; }
tr:nth-child(even) td { background: #f7f7f7; }
blockquote { border-left: 3px solid #999; background: #f6f6f6; margin: 6pt 0; padding: 5pt 8pt; font-size: 8.8pt; column-span: all; }
strong { font-weight: 700; }
hr { border: none; border-top: 1px solid #999; margin: 8pt 0; column-span: all; }
a { color: #0645ad; text-decoration: none; }
h1 + p { column-span: all; }
`;

const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>BugShield</title><style>${css}</style></head><body>${body}</body></html>`;

fs.writeFileSync(HTML, html, 'utf-8');
console.log('HTML written:', HTML);

const profile = path.join(ROOT, '.pdf-profile');
const args = [
  '--headless=new', '--disable-gpu', '--no-sandbox', '--no-pdf-header-footer',
  `--user-data-dir=${profile}`,
  `--print-to-pdf=${PDF}`,
  'file:///' + HTML.replace(/\\/g, '/')
];
execFileSync(browser, args, { stdio: 'inherit', timeout: 180000 });

try { fs.rmSync(profile, { recursive: true, force: true }); } catch {}

if (fs.existsSync(PDF)) {
  const kb = (fs.statSync(PDF).size / 1024).toFixed(1);
  console.log(`PDF written: ${PDF}  (${kb} KB)`);
} else {
  console.error('PDF was not produced.');
  process.exit(1);
}