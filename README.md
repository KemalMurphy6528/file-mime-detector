# File MIME Detector

Determines a file's MIME type by reading magic-number bytes from its header, using a built-in signature database. No filename, no extension, no content sniffing beyond the header.

## Usage

```js
import { detectMime, MimeDetector, SIGNATURES } from 'file-mime-detector';

const header = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
detectMime(header); // -> 'image/png'

// Bring your own signatures, or layer additional ones on top of the built-in list:
const detector = new MimeDetector([
  ...SIGNATURES,
  { mime: 'application/x-my-format', checks: [{ at: 0, check: (b) => b[0] === 0x7F && b[1] === 0x45 } ] }
]);
detector.detect(header);
```

## Why

Extension sniffing is wrong often enough to matter (renamed files, uploads without names, byte streams from sockets). Reading magic numbers from the first few bytes is the reliable alternative, and doing it in pure standard-library code means it works in any JavaScript runtime with no install step.

The trade-off: this library only recognises formats whose magic numbers are unambiguous at a fixed offset. Formats that need deeper parsing — OLE2 compound documents (old Office), ZIP-internal `mimetype` records (ODF, EPUB), or format tables inside an MP4 `stsd` box — are deliberately out of scope. For those, the right answer is a real format parser, not a longer lookup table.

## Edge you'll hit

`detectMime` returns `null` when nothing matches, **not** `application/octet-stream`. A plain-text file, an unknown binary format, and a truncated header all come back as `null`. If your caller needs a default MIME for uploads, apply that fallback yourself rather than expecting one here — collapsing "unknown" into a specific type loses information a downstream component may want.

The MP3 check matches any MPEG audio frame sync (`0xFF` followed by `0xE0`–`0xFF`) or an `ID3` tag. This is intentionally permissive: frame sync is a 11-bit pattern, not a full MPEG header decode, so rare false positives on unrelated binary data are possible. The alternative — fully parsing MPEG frame headers — is out of scope for a magic-number library.
