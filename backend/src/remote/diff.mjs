// Small line diff for the "preview changes before save" step.
// Bounded LCS: for very large files we return a summary instead of stalling.
const MAX_LINES = 3000;

function splitLines(text) {
  return String(text ?? '').replace(/\r\n/g, '\n').split('\n');
}

/** Returns { hunks, added, removed, truncated } where each hunk is {type,line,oldLine,newLine}. */
export function lineDiff(before, after) {
  const oldLines = splitLines(before);
  const newLines = splitLines(after);
  if (oldLines.length > MAX_LINES || newLines.length > MAX_LINES) {
    return {
      truncated: true,
      added: Math.max(0, newLines.length - oldLines.length),
      removed: Math.max(0, oldLines.length - newLines.length),
      hunks: [],
      note: `File terlalu besar untuk diff baris penuh (${oldLines.length} → ${newLines.length} baris).`,
    };
  }

  const n = oldLines.length;
  const m = newLines.length;
  const table = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      table[i][j] = oldLines[i] === newLines[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }

  const hunks = [];
  let i = 0;
  let j = 0;
  let added = 0;
  let removed = 0;
  while (i < n && j < m) {
    if (oldLines[i] === newLines[j]) {
      hunks.push({ type: 'context', line: oldLines[i], oldLine: i + 1, newLine: j + 1 });
      i += 1;
      j += 1;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      hunks.push({ type: 'removed', line: oldLines[i], oldLine: i + 1, newLine: null });
      removed += 1;
      i += 1;
    } else {
      hunks.push({ type: 'added', line: newLines[j], oldLine: null, newLine: j + 1 });
      added += 1;
      j += 1;
    }
  }
  while (i < n) {
    hunks.push({ type: 'removed', line: oldLines[i], oldLine: i + 1, newLine: null });
    removed += 1;
    i += 1;
  }
  while (j < m) {
    hunks.push({ type: 'added', line: newLines[j], oldLine: null, newLine: j + 1 });
    added += 1;
    j += 1;
  }

  // Collapse long unchanged runs so the phone only receives what changed.
  const condensed = [];
  let run = [];
  const flush = () => {
    if (!run.length) return;
    if (run.length > 6) {
      condensed.push(run[0], { type: 'skip', count: run.length - 2 }, run[run.length - 1]);
    } else condensed.push(...run);
    run = [];
  };
  for (const hunk of hunks) {
    if (hunk.type === 'context') run.push(hunk);
    else {
      flush();
      condensed.push(hunk);
    }
  }
  flush();
  return { truncated: false, added, removed, hunks: condensed };
}
