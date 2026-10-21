#!/usr/bin/env node
// contrib/ci/playground/render-terminal.mjs -- one animated terminal SVG
// per session section, from the JSON spec terminal.py wrote.
//
// Usage:
//   render-terminal.mjs SPEC.json OUT_DIR
//
// OUT_DIR gets NN-SLUG.svg per section (NN zero-padded, the section's
// number) and manifest.json listing them, in the order the sections ran.
// The SVGs are self-contained — svg-terminal's animation is SMIL + CSS
// with a static fallback — and each one's element IDs are prefixed with
// its section number, so several can sit on one HTML page (report.py
// embeds them inline) or be linked side by side without collision.
//
// The renderer is svg-terminal's library API rather than its YAML CLI:
// each command line carries its own prompt (the host the shell acted as),
// which the config file format cannot express.

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { generateSvg, mergeConfig } from "svg-terminal";

// Timings tuned for a CI capture: fast typing, output that flows quickly
// enough to watch a whole section in a few seconds, and a pause that
// marks each step.  The animation plays once and freezes on the last
// frame — a screen recording, not a loop.
const TIMING = {
  loop: false,
  defaultTypingDuration: 600,
  defaultSequencePause: 220,
  commandOutputPause: 200,
  outputLineStagger: 30,
  outputEndPause: 50,
};

const WIDTH = 980; // fits 100-character wrapped lines at fontSize 13
const MAX_HEIGHT = 1150; // taller sections scroll inside the terminal

/** Prefix every id= / url(#…) reference with the section's number, so
 *  several SVGs can share one page.  svg-terminal's ids are fixed
 *  (terminalViewport, shadow, cmdrev-N), so a string rewrite is exact. */
function prefixIds(svg, prefix) {
  return svg
    .replace(/\bid="([^"]+)"/g, (_, id) => `id="${prefix}${id}"`)
    .replace(/url\(#([^)]+)\)/g, (_, id) => `url(#${prefix}${id})`);
}

async function main() {
  const [specPath, outDir] = process.argv.slice(2);
  if (!specPath || !outDir) {
    console.error("usage: render-terminal.mjs SPEC.json OUT_DIR");
    process.exit(2);
  }
  const spec = JSON.parse(await (await import("node:fs/promises")).readFile(specPath, "utf8"));
  await mkdir(outDir, { recursive: true });

  const manifest = [];
  for (const section of spec) {
    const nn = String(section.index).padStart(2, "0");
    const name = `${nn}-${section.slug}.svg`;
    const config = mergeConfig({
      // `blocks` is required by the config schema; the sequences carry
      // the actual content.
      blocks: [{ block: "custom", config: { command: "kuipa", lines: [""] } }],
      window: {
        width: WIDTH,
        title: `kuipa playground — ${section.title}`,
        autoHeight: true,
        maxHeight: MAX_HEIGHT,
      },
      terminal: { fontSize: 13, lineHeight: 1.7, prompt: "$ " },
      animation: TIMING,
      effects: { scanlines: false, shadow: true },
      accessibilityLabel: `Terminal capture of the playground session section "${section.title}"`,
    });
    let svg = generateSvg(section.sequences, config);
    svg = prefixIds(svg, `s${section.index}-`);
    await writeFile(path.join(outDir, name), svg + "\n");
    manifest.push({ index: section.index, slug: section.slug, file: name });
  }
  await writeFile(
    path.join(outDir, "manifest.json"),
    JSON.stringify({ width: WIDTH, captures: manifest }, null, 1) + "\n",
  );
  console.error(
    `[playground-terminal] wrote ${manifest.length} SVG captures to ${outDir}`,
  );
}

main().catch((err) => {
  console.error(`[playground-terminal] ${err.stack ?? err}`);
  process.exit(1);
});
