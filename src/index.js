import { MimeDetector } from './core.js';
import { SIGNATURES } from './signatures.js';

const DEFAULT_DETECTOR = new MimeDetector(SIGNATURES);

export { MimeDetector, SIGNATURES };

export function detectMime(bytes) {
  return DEFAULT_DETECTOR.detect(bytes);
}
