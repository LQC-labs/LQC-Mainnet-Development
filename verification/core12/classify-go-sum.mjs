import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

function parse(bytes) {
  const rows = new Map();
  const malformed = [];
  const duplicates = [];
  const lines = bytes.toString('utf8').split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (line === '' && index === lines.length - 1) continue;
    const match = /^(\S+) (v\S+) (h1:[A-Za-z0-9+/]{43}=)$/.exec(line);
    if (!match) { malformed.push({ line: index + 1, text: line }); continue; }
    const key = `${match[1]} ${match[2]}`;
    if (rows.has(key)) duplicates.push(key);
    rows.set(key, match[3]);
  }
  return { rows, malformed, duplicates };
}
const [beforePath, afterPath] = process.argv.slice(2);
if (!beforePath || !afterPath) throw new Error('Expected before and after go.sum paths');
const beforeBytes = readFileSync(beforePath);
const afterBytes = readFileSync(afterPath);
const before = parse(beforeBytes);
const after = parse(afterBytes);
const added = [], removed = [], changed = [];
for (const [key, hash] of after.rows) {
  if (!before.rows.has(key)) added.push({ key, hash });
  else if (before.rows.get(key) !== hash) changed.push({ key, before: before.rows.get(key), after: hash });
}
for (const [key, hash] of before.rows) if (!after.rows.has(key)) removed.push({ key, hash });
const invalid = before.malformed.length + after.malformed.length + before.duplicates.length + after.duplicates.length > 0;
const byteIdentical = beforeBytes.equals(afterBytes);
const semanticIdentical = added.length + removed.length + changed.length === 0;
const classification = invalid ? 'invalid-format-or-duplicate-entries'
  : byteIdentical ? 'unchanged'
  : removed.length || changed.length ? 'removed-or-replaced-checksums-review-required'
  : added.length ? 'additions-only-review-required'
  : 'format-or-order-only-review-required';
console.log(JSON.stringify({
  beforeSha256: createHash('sha256').update(beforeBytes).digest('hex'),
  afterSha256: createHash('sha256').update(afterBytes).digest('hex'),
  classification, byteIdentical, semanticIdentical, added, removed, changed,
  malformed: { before: before.malformed, after: after.malformed },
  duplicates: { before: before.duplicates, after: after.duplicates },
  notice: 'Structural classification only. Addition-only does not establish authenticity or permit hash drift. Review module versions, official checksum evidence and command logs before accepting any change.'
}, null, 2));
if (invalid) process.exitCode = 1;
