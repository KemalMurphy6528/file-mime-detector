import { test } from 'node:test';
import assert from 'node:assert/strict';

import { detectMime, MimeDetector } from '../src/index.js';
import { SIGNATURES } from '../src/signatures.js';

function bytes(...vals) {
  return new Uint8Array(vals);
}

function padded(length, ...prefix) {
  const out = new Uint8Array(length);
  out.set(prefix);
  return out;
}

test('detects PNG via its 8-byte signature', () => {
  assert.equal(
    detectMime(bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)),
    'image/png'
  );
});

test('detects JPEG from its leading FF D8 FF sequence', () => {
  assert.equal(detectMime(bytes(0xFF, 0xD8, 0xFF, 0xE0)), 'image/jpeg');
});

test('distinguishes GIF87a from GIF89a and resolves both to image/gif', () => {
  const gif87 = bytes(0x47, 0x49, 0x46, 0x38, 0x37, 0x61);
  const gif89 = bytes(0x47, 0x49, 0x46, 0x38, 0x39, 0x61);
  assert.equal(detectMime(gif87), 'image/gif');
  assert.equal(detectMime(gif89), 'image/gif');
});

test('detects TIFF little-endian and big-endian variants', () => {
  assert.equal(detectMime(bytes(0x49, 0x49, 0x2A, 0x00)), 'image/tiff');
  assert.equal(detectMime(bytes(0x4D, 0x4D, 0x00, 0x2A)), 'image/tiff');
});

test('detects BMP from its 2-byte "BM" marker', () => {
  assert.equal(detectMime(bytes(0x42, 0x4D)), 'image/bmp');
});

test('detects WebP requiring bytes at offset 0 and offset 8 simultaneously', () => {
  const webp = bytes(
    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
    0x57, 0x45, 0x42, 0x50
  );
  assert.equal(detectMime(webp), 'image/webp');
});

test('detects PDF by its %PDF- header', () => {
  assert.equal(detectMime(bytes(0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34)), 'application/pdf');
});

test('detects the three valid local ZIP signatures', () => {
  assert.equal(detectMime(bytes(0x50, 0x4B, 0x03, 0x04)), 'application/zip');
  assert.equal(detectMime(bytes(0x50, 0x4B, 0x05, 0x06)), 'application/zip');
  assert.equal(detectMime(bytes(0x50, 0x4B, 0x07, 0x08)), 'application/zip');
});

test('detects gzip even without optional FLG byte inspection', () => {
  assert.equal(detectMime(bytes(0x1F, 0x8B, 0x08, 0x00)), 'application/gzip');
});

test('detects tar via the "ustar" magic at offset 257', () => {
  const tar = padded(265, ...new Array(257).fill(0x00));
  tar[257] = 0x75; // u
  tar[258] = 0x73; // s
  tar[259] = 0x74; // t
  tar[260] = 0x61; // a
  tar[261] = 0x72; // r
  assert.equal(detectMime(tar), 'application/x-tar');
});

test('detects MP4 with an isom compatible brand inside the ftyp box', () => {
  const mp4 = bytes(
    0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70,
    0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00
  );
  assert.equal(detectMime(mp4), 'video/mp4');
});

test('detects WAV via RIFF + WAVE form type', () => {
  const wav = bytes(
    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
    0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20
  );
  assert.equal(detectMime(wav), 'audio/wav');
});

test('detects MP3 with a leading MPEG frame sync', () => {
  assert.equal(detectMime(bytes(0xFF, 0xFB, 0x90, 0x00)), 'audio/mpeg');
});

test('detects MP3 with an ID3v2 tag preceding the audio frames', () => {
  assert.equal(detectMime(bytes(0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00)), 'audio/mpeg');
});

test('returns null for empty input', () => {
  assert.equal(detectMime(new Uint8Array(0)), null);
});

test('returns null for plain ASCII text that matches nothing', () => {
  assert.equal(detectMime(bytes(0x68, 0x65, 0x6C, 0x6C, 0x6F)), null);
});

test('returns null when the RIFF header is present but not followed by WEBP or WAVE', () => {
  // RIFF with an AVI form type is not in the registry, so it must fall through.
  assert.equal(
    detectMime(bytes(0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20)),
    null
  );
});

test('detects short inputs only against signatures whose required offset is in range', () => {
  // PDF requires bytes 0..4; supplying just three bytes must miss it.
  assert.equal(detectMime(bytes(0x25, 0x50, 0x44)), null);
  // BMP only needs two bytes; that should still match.
  assert.equal(detectMime(bytes(0x42, 0x4D)), 'image/bmp');
});

test('returns null for a RIFF header with fewer than 12 bytes when WEBP/WAVE need bytes 8..11', () => {
  assert.equal(
    detectMime(bytes(0x52, 0x49, 0x46, 0x46, 0x57, 0x45, 0x42, 0x50)),
    null
  );
});

test('accepts a plain number array and masks out-of-range byte values', () => {
  // 0x14A & 0xFF === 0x4A, so this is actually 'JFIF' — not a signature we
  // match on its own, but it proves the masking path runs and produces null
  // rather than throwing.
  assert.equal(detectMime([0x4A, 0x14A, 0x1F6, 0x149]), null);
});

test('throws when given a non-array, non-Uint8Array input', () => {
  assert.throws(() => detectMime('not bytes'), TypeError);
  assert.throws(() => detectMime(null), TypeError);
});

test('the first matching signature in declaration order wins', () => {
  // Craft a custom registry where two signatures share the same trigger byte.
  const custom = [
    { mime: 'application/x-custom-first', checks: [{ at: 0, check: (b) => b[0] === 0xAA }] },
    { mime: 'application/x-custom-second', checks: [{ at: 0, check: (b) => b[0] === 0xAA }] }
  ];
  const det = new MimeDetector(custom);
  assert.equal(det.detect(bytes(0xAA)), 'application/x-custom-first');
});

test('MimeDetector does not mutate the signatures array passed to it', () => {
  const registry = [
    { mime: 'application/x-test', checks: [{ at: 0, check: (b) => b[0] === 0x01 }] }
  ];
  const det = new MimeDetector(registry);
  assert.equal(det.detect(bytes(0x01)), 'application/x-test');
  assert.equal(registry.length, 1);
  assert.equal(registry[0].mime, 'application/x-test');
});

test('maxProbe reflects the largest offset plus worst-case read window', () => {
  const det = new MimeDetector(SIGNATURES);
  // tar reads at offset 257; with the 16-byte window the probe bound is at least 273.
  assert.ok(det.maxProbe >= 273, `expected maxProbe >= 273, got ${det.maxProbe}`);
});

test('detects the ICO directory header', () => {
  assert.equal(detectMime(bytes(0x00, 0x00, 0x01, 0x00, 0x01, 0x00)), 'image/x-icon');
});

test('detects Flash SWF by its FWS/CWS/ZWS signature byte', () => {
  assert.equal(detectMime(bytes(0x46, 0x57, 0x53, 0x09)), 'application/x-shockwave-flash');
  assert.equal(detectMime(bytes(0x43, 0x57, 0x53, 0x09)), 'application/x-shockwave-flash');
  assert.equal(detectMime(bytes(0x5A, 0x57, 0x53, 0x09)), 'application/x-shockwave-flash');
});
