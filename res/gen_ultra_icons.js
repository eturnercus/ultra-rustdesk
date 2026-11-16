// Ultra RustDesk icon generator: renders the icon (a monitor with a lightning bolt on a
// violet-to-blue tile) into every PNG/ICO the platforms need. No dependencies: plain Node.
//   node res/gen_ultra_icons.js
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');
const C1 = [123, 47, 247]; // #7b2ff7, top left
const C2 = [31, 162, 255]; // #1fa2ff, bottom right

// Geometry in a 1024 x 1024 design space.
const TILE_R = 224;
const MON = { x0: 192, y0: 248, x1: 832, y1: 704, r: 56, w: 56 };
const NECK = { x0: 462, y0: 704, x1: 562, y1: 792 };
const BASE = { x0: 352, y0: 786, x1: 672, y1: 840, r: 27 };
const BOLT = [[566, 310], [398, 512], [506, 512], [458, 660], [632, 446], [526, 446], [598, 310]];
const GLYPH = { x0: 164, y0: 220, x1: 860, y1: 840 }; // bounds of everything white

function sdRoundRect(px, py, b) {
  const cx = (b.x0 + b.x1) / 2, cy = (b.y0 + b.y1) / 2;
  const r = b.r || 0;
  const qx = Math.abs(px - cx) - ((b.x1 - b.x0) / 2 - r);
  const qy = Math.abs(py - cy) - ((b.y1 - b.y0) / 2 - r);
  const ox = Math.max(qx, 0), oy = Math.max(qy, 0);
  return Math.hypot(ox, oy) + Math.min(Math.max(qx, qy), 0) - r;
}

function inPolygon(px, py, pts) {
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const [xi, yi] = pts[i], [xj, yj] = pts[j];
    if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function inGlyph(x, y) {
  if (Math.abs(sdRoundRect(x, y, MON)) <= MON.w / 2) return true;
  if (x >= NECK.x0 && x <= NECK.x1 && y >= NECK.y0 && y <= NECK.y1) return true;
  if (sdRoundRect(x, y, BASE) <= 0) return true;
  return inPolygon(x, y, BOLT);
}

/**
 * kind: 'tile' (rounded square), 'round' (circle), 'glyph' (white glyph on transparent).
 * For 'glyph', `fill` is the fraction of the canvas the glyph's larger side takes.
 */
function render(size, kind, fill = 0.56) {
  const SS = size >= 512 ? 3 : 4;
  const px = Buffer.alloc(size * size * 4);
  let toDesign;
  if (kind === 'glyph') {
    const gw = GLYPH.x1 - GLYPH.x0, gh = GLYPH.y1 - GLYPH.y0;
    const scale = Math.max(gw, gh) / (size * fill);
    const cx = (GLYPH.x0 + GLYPH.x1) / 2, cy = (GLYPH.y0 + GLYPH.y1) / 2;
    toDesign = (u, v) => [cx + (u - size / 2) * scale, cy + (v - size / 2) * scale];
  } else {
    const scale = 1024 / size;
    toDesign = (u, v) => [u * scale, v * scale];
  }
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const [dx, dy] = toDesign(x + (sx + 0.5) / SS, y + (sy + 0.5) / SS);
          let sr, sg, sb, sa;
          if (kind === 'glyph') {
            if (!inGlyph(dx, dy)) continue;
            sr = sg = sb = 255; sa = 255;
          } else {
            const inShape = kind === 'round'
              ? Math.hypot(dx - 512, dy - 512) <= 512
              : sdRoundRect(dx, dy, { x0: 0, y0: 0, x1: 1024, y1: 1024, r: TILE_R }) <= 0;
            if (!inShape) continue;
            if (inGlyph(dx, dy)) {
              sr = sg = sb = 255;
            } else {
              const t = Math.min(1, Math.max(0, (dx + dy) / 2048));
              sr = C1[0] + (C2[0] - C1[0]) * t;
              sg = C1[1] + (C2[1] - C1[1]) * t;
              sb = C1[2] + (C2[2] - C1[2]) * t;
            }
            sa = 255;
          }
          r += sr; g += sg; b += sb; a += sa;
        }
      }
      const n = SS * SS, i = (y * size + x) * 4;
      if (a > 0) {
        // average colour over covered samples, alpha over all samples
        const cov = a / 255;
        px[i] = Math.round(r / cov); px[i + 1] = Math.round(g / cov); px[i + 2] = Math.round(b / cov);
        px[i + 3] = Math.round(a / n);
      }
    }
  }
  return png(size, px);
}

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
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}
function ico(images) {
  // images: [{size, data(png)}]; PNG-compressed entries (Windows Vista and later).
  const head = Buffer.alloc(6); head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(images.length, 4);
  const dir = Buffer.alloc(16 * images.length);
  let offset = 6 + dir.length;
  images.forEach((img, i) => {
    const o = i * 16;
    dir[o] = img.size >= 256 ? 0 : img.size; dir[o + 1] = img.size >= 256 ? 0 : img.size;
    dir[o + 2] = 0; dir[o + 3] = 0; dir.writeUInt16LE(1, o + 4); dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(img.data.length, o + 8); dir.writeUInt32LE(offset, o + 12);
    offset += img.data.length;
  });
  return Buffer.concat([head, dir, ...images.map((i) => i.data)]);
}

const cache = new Map();
function tile(size) {
  if (!cache.has(size)) cache.set(size, render(size, 'tile'));
  return cache.get(size);
}
function write(rel, data) {
  const p = path.join(ROOT, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, data);
  console.log('wrote', rel, data.length);
}
const icoOf = (sizes) => ico(sizes.map((size) => ({ size, data: tile(size) })));

// Desktop
write('res/icon.png', tile(1024));
write('res/mac-icon.png', tile(1024));
write('res/32x32.png', tile(32));
write('res/64x64.png', tile(64));
write('res/128x128.png', tile(128));
write('res/128x128@2x.png', tile(256));
write('res/icon.ico', icoOf([16, 24, 32, 48, 64, 128, 256]));
write('res/tray-icon.ico', icoOf([16, 24, 32]));
write('flutter/windows/runner/resources/app_icon.ico', icoOf([16, 24, 32, 48, 64, 128, 256]));
write('flutter/assets/icon.ico', icoOf([16, 32, 48, 256]));

// Android
const dens = { mdpi: 1, hdpi: 1.5, xhdpi: 2, xxhdpi: 3, xxxhdpi: 4 };
for (const [d, k] of Object.entries(dens)) {
  const dir = `flutter/android/app/src/main/res/mipmap-${d}`;
  write(`${dir}/ic_launcher.png`, tile(48 * k));
  write(`${dir}/ic_launcher_round.png`, render(48 * k, 'round'));
  // Adaptive foreground: 108dp canvas, keep the glyph inside the 66dp safe zone.
  write(`${dir}/ic_launcher_foreground.png`, render(108 * k, 'glyph', 0.5));
  write(`${dir}/ic_stat_logo.png`, render(24 * k, 'glyph', 0.9));
}
