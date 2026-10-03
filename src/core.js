/**
 * The detection engine. Signature checks are authored as small closures so they
 * can express arbitrary byte-level predicates (ranges, OR-branches, masks)
 * without having to invent a mini-DSL. The detector itself stays trivial and
 * therefore cheap to audit.
 */
export class MimeDetector {
  /**
   * @param {ReadonlyArray<{ mime: string, checks: Array<{ at: number, check: (bytes: Uint8Array) => boolean }> }>} signatures
   *   Ordered list of signatures. Order matters: earlier entries win ties.
   */
  constructor(signatures) {
    if (!Array.isArray(signatures)) {
      throw new TypeError('MimeDetector requires a signatures array');
    }
    // Copy defensively so callers can't mutate behaviour after construction.
    this._signatures = signatures.map((entry) => ({
      mime: entry.mime,
      checks: entry.checks.map((c) => ({ at: c.at, check: c.check }))
    }));
    // Pre-compute the largest offset any signature can touch so we know how
    // much of the input is actually required before we can give a definitive
    // answer. This drives the early-null result for short inputs.
    let max = 0;
    for (const entry of this._signatures) {
      for (const c of entry.checks) {
        // The check closure may read several bytes after `at`; since we do
        // not model the read extent, assume a worst-case of 16 bytes. The
        // built-in registry's checks read at most 12, so this is safe with
        // margin, and it keeps the worst-case bound stable when users add
        // their own signatures.
        if (c.at + 16 > max) max = c.at + 16;
      }
    }
    this._maxProbe = max;
  }

  /**
   * The largest offset any registered signature can meaningfully read. Inputs
   * shorter than this are only matched against signatures that do not require
   * the missing bytes.
   */
  get maxProbe() {
    return this._maxProbe;
  }

  /**
   * Normalise the input into a {@link Uint8Array} with masked byte values.
   * Regular `number[]` inputs are supported for convenience when reading a
   * few bytes via `Buffer.readUInt8` style code; values outside 0–255 are
   * masked because Node's `Buffer` methods never produce them but some hand-
   * written decoders do.
   *
   * @param {Uint8Array | number[]} input
   * @returns {Uint8Array}
   */
  static normalise(input) {
    if (input instanceof Uint8Array) {
      return input;
    }
    if (!Array.isArray(input)) {
      throw new TypeError('detect() expects a Uint8Array or number array');
    }
    const out = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      const v = input[i];
      if (typeof v !== 'number') {
        throw new TypeError(`Byte at index ${i} is not a number`);
      }
      out[i] = v & 0xFF;
    }
    return out;
  }

  /**
   * Detect a MIME type from the leading bytes of a file.
   *
   * Returns the MIME string of the first matching signature, or `null` when
   * nothing matches. Signatures are evaluated in declaration order; the first
   * to match wins. A check is only consulted when its starting offset `at` is
   * within the input length, so short inputs safely fail checks that read
   * beyond them rather than throwing on out-of-range access.
   *
   * @param {Uint8Array | number[]} bytes
   * @returns {string | null}
   */
  detect(bytes) {
    const buf = MimeDetector.normalise(bytes);
    for (const entry of this._signatures) {
      for (const c of entry.checks) {
        if (c.at >= buf.length) continue;
        // Inside `check`, accesses past the buffer length yield `undefined`,
        // and arithmetic with `undefined` produces `NaN`, which compares
        // false to everything. That means a check that reads, say, bytes
        // 8–11 fails safely if only 9 bytes were supplied, without us having
        // to model the exact read extent per check.
        if (c.check(buf)) {
          return entry.mime;
        }
      }
    }
    return null;
  }
}
