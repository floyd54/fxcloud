#!/usr/bin/env node
/*
 * Generates the PWA / favicon icons into frontend/assets/icons/.
 *
 *   node frontend/tests/gen-icons.js
 *
 * Committed output: the icons are embedded into the binary at build time
 * (rust-embed), so this script is re-run only when the artwork changes.
 * No image tooling exists on the build host by design - the PNG is written
 * here by hand (zlib for the IDAT stream, CRC32 per chunk), which keeps the
 * whole pipeline dependency-free and byte-reproducible.
 *
 * The mark matches the Android launcher icon (concepts/android.md): a
 * dark vertical gradient (#1E2430 -> #14161B), the brand cloud as a
 * soft blue - fill 45% / rim 70% of the accent #0082c9, the same
 * AARRGGBB values the Android XML carries - and a white fx inside.
 * Full-bleed: no pre-rounded corners, because every consumer (iOS
 * home screen, Android launcher masks, Chrome) applies its own mask and a
 * maskable icon must bleed to the edge. The cloud stays inside the maskable
 * safe zone (central 62.5%), the maskable variant gets extra padding.
 */
"use strict";

const zlib = require("zlib");
const fs = require("fs");
const path = require("path");

const ACCENT = [0x00, 0x82, 0xc9];
const LETTER = [0xe6, 0xe9, 0xee]; // the fx, white like the app icon
const BG_TOP = [0x1e, 0x24, 0x30];
const BG_BOTTOM = [0x14, 0x16, 0x1b];
const SS = 4; // supersampling: SS x SS sub-pixels per output pixel
// The cloud's rim: stroke width 2.4 in the app icon's 108 grid, halved
// for a band centred on the outline; the fx strokes likewise (3.6/3.2).
const RIM_HALF = (2.4 / 108) / 2;
const FX_HW = (3.6 / 108) / 2;
const FX_HW_CROSS = (3.2 / 108) / 2;
// The fx in icon space (0..1), the same letterforms the Android XML
// draws: f hook + stem, crossbar, and the x - inside the cloud. This
// cloud is narrower than the launcher's, so the letters shrink to the
// same fraction of it (46-49% of the cloud's width).
const FX_SCALE = 0.8;
const FX_CY = 0.483;
const FX = [
  [0.426, 0.410, 0.426, 0.595, FX_HW], // f stem
  [0.426, 0.410, 0.434, 0.394, FX_HW], // f flag
  [0.434, 0.394, 0.452, 0.389, FX_HW], // f flag
  [0.452, 0.389, 0.472, 0.419, FX_HW], // f flag
  [0.380, 0.484, 0.472, 0.484, FX_HW_CROSS], // f crossbar
  [0.509, 0.410, 0.620, 0.595, FX_HW], // x
  [0.620, 0.410, 0.509, 0.595, FX_HW], // x
].map(([ax, ay, bx, by, hw]) => [
  0.5 + (ax - 0.5) * FX_SCALE,
  FX_CY + (ay - FX_CY) * FX_SCALE,
  0.5 + (bx - 0.5) * FX_SCALE,
  FX_CY + (by - FX_CY) * FX_SCALE,
  hw * FX_SCALE,
]);

// ---- PNG encoder (subset: RGBA8, no interlace, filter None) -------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

function encodePng(width, height, rgba) {
  // Filter byte 0 (None) in front of every scanline.
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    const off = y * (width * 4 + 1);
    raw[off] = 0;
    rgba.copy(raw, off + 1, y * width * 4, (y + 1) * width * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ---- the mark -----------------------------------------------------------

// Signed distances in a unit coordinate system (0..1 of the icon), cloud
// centered horizontally, sitting slightly below center so it reads balanced
// once a launcher crops top/bottom.
function sdCircle(px, py, cx, cy, r) {
  return Math.hypot(px - cx, py - cy) - r;
}
function cloudDistance(u, v, scale) {
  // Scale the whole cloud about its center; scale < 1 pads for maskable.
  const x = (u - 0.5) / scale + 0.5;
  const y = (v - 0.52) / scale + 0.52;
  // Three puffs only: the old base box sat at the coordinate origin and
  // painted a stray blob into the top-left corner instead of a base.
  const d2 = sdCircle(x, y, 0.37, 0.55, 0.09); // left puff
  const d3 = sdCircle(x, y, 0.5, 0.47, 0.13); // top puff
  const d4 = sdCircle(x, y, 0.63, 0.55, 0.09); // right puff
  return Math.min(d2, d3, d4);
}

function sdSegment(px, py, ax, ay, bx, by) {
  const pax = px - ax;
  const pay = py - ay;
  const bax = bx - ax;
  const bay = by - ay;
  const h = Math.min(1, Math.max(0, (pax * bax + pay * bay) / (bax * bax + bay * bay)));
  return Math.hypot(pax - bax * h, pay - bay * h);
}

function mix(a, b, t) {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

function render(size, scale) {
  const px = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = (x + (sx + 0.5) / SS) / size;
          const v = (y + (sy + 0.5) / SS) / size;
          // 1. the gradient, full-bleed and unscaled
          let col = mix(BG_TOP, BG_BOTTOM, v);
          // 2. the cloud: rim band first, then the soft fill
          const d = cloudDistance(u, v, scale);
          if (Math.abs(d) <= RIM_HALF) col = mix(col, ACCENT, 0.7);
          else if (d < 0) col = mix(col, ACCENT, 0.45);
          // 3. the fx on top, scaled with the cloud (maskable padding)
          const ix = (u - 0.5) / scale + 0.5;
          const iy = (v - 0.52) / scale + 0.52;
          let fx = Infinity;
          for (const [ax, ay, bx, by, hw] of FX) {
            fx = Math.min(fx, sdSegment(ix, iy, ax, ay, bx, by) - hw);
          }
          if (fx < 0) col = LETTER;
          r += col[0];
          g += col[1];
          b += col[2];
        }
      }
      const n = SS * SS;
      const o = (y * size + x) * 4;
      px[o] = Math.round(r / n);
      px[o + 1] = Math.round(g / n);
      px[o + 2] = Math.round(b / n);
      px[o + 3] = 255;
    }
  }
  return encodePng(size, size, px);
}

// ---- entry point --------------------------------------------------------

const OUT_DIR = path.join(__dirname, "..", "assets", "icons");
const TARGETS = [
  // file, size, cloud scale (maskable gets padding so the launcher mask
  // never clips a puff)
  ["icon-32.png", 32, 1],
  ["icon-192.png", 192, 1],
  ["icon-512.png", 512, 1],
  ["icon-maskable-512.png", 512, 0.86],
  ["apple-touch-icon-180.png", 180, 1],
];

/** Decode one of our own PNGs back to raw RGBA (filter None only). */
function decodePng(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error("not a PNG");
  let off = 8;
  let width = 0;
  let height = 0;
  const idat = [];
  while (off < buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString("ascii", off + 4, off + 8);
    if (type === "IHDR") {
      width = buf.readUInt32BE(off + 8);
      height = buf.readUInt32BE(off + 12);
      if (buf[off + 16] !== 8 || buf[off + 17] !== 6) {
        throw new Error("unexpected PNG format");
      }
    } else if (type === "IDAT") {
      idat.push(buf.subarray(off + 8, off + 8 + len));
    }
    off += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const px = Buffer.alloc(width * height * 4);
  const stride = width * 4 + 1;
  for (let y = 0; y < height; y++) {
    if (raw[y * stride] !== 0) throw new Error("unexpected filter byte");
    raw.copy(px, y * width * 4, y * stride + 1, y * stride + 1 + width * 4);
  }
  return { width, height, px };
}

/**
 * --check: the committed icons must be exactly what this script renders.
 * Compared at pixel level (not byte level): the deflate stream may differ
 * between zlib builds, the artwork may not.
 */
function check() {
  let failed = false;
  for (const [name, size, scale] of TARGETS) {
    const file = path.join(OUT_DIR, name);
    let stored;
    try {
      stored = decodePng(fs.readFileSync(file));
    } catch (e) {
      console.error(`${name}: unreadable (${e.message})`);
      failed = true;
      continue;
    }
    const fresh = render(size, scale);
    const want = decodePng(fresh);
    if (
      stored.width !== want.width ||
      stored.height !== want.height ||
      !stored.px.equals(want.px)
    ) {
      console.error(`${name}: does not match gen-icons.js - re-run it`);
      failed = true;
    }
  }
  if (failed) process.exit(1);
  console.log(`icons match gen-icons.js (${TARGETS.length} files)`);
}

if (process.argv.includes("--check")) {
  check();
} else {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const [name, size, scale] of TARGETS) {
    const buf = render(size, scale);
    fs.writeFileSync(path.join(OUT_DIR, name), buf);
    console.log(`${name}: ${size}x${size}, ${buf.length} bytes`);
  }
}
