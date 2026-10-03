/**
 * Signature registry used by {@link MimeDetector}.
 *
 * Each entry describes how to recognise a single MIME type by reading bytes
 * at a fixed offset from the start of the file. An entry may carry one or
 * more `check` callbacks; every callback whose `at` offset is within the
 * supplied byte range must return `true` for the entry to match.
 *
 * The signatures are ordered so that the most specific (e.g. PDF) appear
 * before the more generic (e.g. ZIP-based containers). This mirrors the
 * common situation where a container format can hold several inner types
 * that share a leading byte sequence. We deliberately keep this as a flat,
 * hand-maintained list rather than attempting OLE2 compound-document parsing
 * or ZIP central-directory inspection: the cost of extra coverage is not
 * worth the complexity or the larger error surface for the formats we
 * actually commit to.
 *
 * @typedef {(bytes: Uint8Array) => boolean} ByteCheck
 * @typedef {{ mime: string, checks: Array<{ at: number, check: ByteCheck }> }} Signature
 */

export const SIGNATURES = [
  {
    mime: 'image/jpeg',
    checks: [
      { at: 0, check: (b) => b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF }
    ]
  },
  {
    mime: 'image/png',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47 &&
        b[4] === 0x0D && b[5] === 0x0A && b[6] === 0x1A && b[7] === 0x0A }
    ]
  },
  {
    mime: 'image/gif',
    checks: [
      { at: 0, check: (b) => b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38 && b[4] === 0x37 && b[5] === 0x61 },
      { at: 0, check: (b) => b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38 && b[4] === 0x39 && b[5] === 0x61 }
    ]
  },
  {
    mime: 'image/bmp',
    checks: [
      { at: 0, check: (b) => b[0] === 0x42 && b[1] === 0x4D }
    ]
  },
  {
    mime: 'image/webp',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
        b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50 }
    ]
  },
  {
    mime: 'image/tiff',
    checks: [
      { at: 0, check: (b) => b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2A && b[3] === 0x00 },
      { at: 0, check: (b) => b[0] === 0x4D && b[1] === 0x4D && b[2] === 0x00 && b[3] === 0x2A }
    ]
  },
  {
    mime: 'image/x-icon',
    checks: [
      { at: 0, check: (b) => b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00 }
    ]
  },
  {
    mime: 'application/pdf',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46 && b[4] === 0x2D }
    ]
  },
  {
    mime: 'application/postscript',
    checks: [
      { at: 0, check: (b) => b[0] === 0x25 && b[1] === 0x21 && b[2] === 0x50 && b[3] === 0x53 }
    ]
  },
  {
    mime: 'application/zip',
    checks: [
      { at: 0, check: (b) => b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x03 && b[3] === 0x04 },
      { at: 0, check: (b) => b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x05 && b[3] === 0x06 },
      { at: 0, check: (b) => b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x07 && b[3] === 0x08 }
    ]
  },
  {
    mime: 'application/gzip',
    checks: [
      { at: 0, check: (b) => b[0] === 0x1F && b[1] === 0x8B && b[2] === 0x08 }
    ]
  },
  {
    mime: 'application/x-bzip2',
    checks: [
      { at: 0, check: (b) => b[0] === 0x42 && b[1] === 0x5A && b[2] === 0x68 }
    ]
  },
  {
    mime: 'application/x-7z-compressed',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC && b[3] === 0xAF &&
        b[4] === 0x27 && b[5] === 0x1C }
    ]
  },
  {
    mime: 'application/x-rar-compressed',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21 &&
        b[4] === 0x1A && b[5] === 0x07 && b[6] === 0x00 }
    ]
  },
  {
    mime: 'application/x-tar',
    checks: [
      { at: 257, check: (b) =>
        b[257] === 0x75 && b[258] === 0x73 && b[259] === 0x74 && b[260] === 0x61 &&
        b[261] === 0x72 }
    ]
  },
  {
    mime: 'application/x-shockwave-flash',
    checks: [
      { at: 0, check: (b) =>
        (b[0] === 0x46 || b[0] === 0x43 || b[0] === 0x5A) &&
        b[1] === 0x57 && b[2] === 0x53 }
    ]
  },
  {
    mime: 'application/ogg',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53 }
    ]
  },
  {
    mime: 'audio/midi',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x4D && b[1] === 0x54 && b[2] === 0x68 && b[3] === 0x64 }
    ]
  },
  {
    mime: 'video/mp4',
    checks: [
      { at: 4, check: (b) =>
        b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70 &&
        (b[8] === 0x69 && b[9] === 0x73 && b[10] === 0x6F && b[11] === 0x6D) ||
        (b[8] === 0x6D && b[9] === 0x70 && b[10] === 0x34 && b[11] === 0x32) ||
        (b[8] === 0x4D && b[9] === 0x34 && b[10] === 0x56 && b[11] === 0x20) ||
        (b[8] === 0x61 && b[9] === 0x76 && b[10] === 0x63 && b[11] === 0x31) ||
        (b[8] === 0x68 && b[9] === 0x65 && b[10] === 0x69 && b[11] === 0x63) ||
        (b[8] === 0x64 && b[9] === 0x61 && b[10] === 0x73 && b[11] === 0x68) }
    ]
  },
  {
    mime: 'audio/wav',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
        b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45 }
    ]
  },
  {
    mime: 'audio/mpeg',
    checks: [
      { at: 0, check: (b) => b[0] === 0xFF && (b[1] & 0xE0) === 0xE0 },
      { at: 0, check: (b) => b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33 }
    ]
  },
  {
    mime: 'audio/flac',
    checks: [
      { at: 0, check: (b) => b[0] === 0x66 && b[1] === 0x4C && b[2] === 0x61 && b[3] === 0x43 }
    ]
  },
  {
    mime: 'audio/ogg',
    checks: [
      { at: 0, check: (b) =>
        b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53 &&
        b[4] === 0x4F && b[5] === 0x67 && b[6] === 0x67 && b[7] === 0x53 }
    ]
  }
];
