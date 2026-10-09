/**
 * Tolerant JSON parsing for model output.
 *
 * Models — especially smaller or quantised ones, even in JSON mode — do not always
 * return a clean object. The ones seen in practice: a ```json fence around it, a
 * sentence before it, and (the common one) a *double-escaped* body where the content
 * is `{\"k\":\"v\"}` rather than `{"k":"v"}`. Strict `JSON.parse` rejects all three
 * and the caller then fails closed, which is correct but throws away good answers.
 *
 * `parseLooseJson` recovers these without ever inventing data: it only reshapes what
 * the model actually returned, and returns null when nothing parses. Callers still
 * validate the parsed shape, so a recovered-but-wrong object is rejected downstream
 * exactly as a strict parse failure would be.
 */

/** Parse model text into an object, tolerating fences, prose, and double-escaping. */
export function parseLooseJson(raw: string): unknown {
  const candidates = extractCandidates(raw);
  for (const candidate of candidates) {
    const parsed = tryParse(candidate);
    if (parsed !== undefined) {
      return parsed;
    }
  }
  return null;
}

function tryParse(text: string): unknown | undefined {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Progressively-looser forms of the text to attempt, most-literal first. */
function extractCandidates(raw: string): string[] {
  const out: string[] = [];
  const add = (s: string): void => {
    const t = s.trim();
    if (t.length > 0 && !out.includes(t)) {
      out.push(t);
    }
  };

  const trimmed = raw.trim();
  add(trimmed);

  // Strip a ```json … ``` (or bare ```) fence.
  const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed);
  if (fence !== null) {
    add(fence[1]!);
  }

  // The first balanced {...} block, ignoring braces inside strings.
  const block = firstJsonBlock(trimmed);
  if (block !== null) {
    add(block);
    // Double-escaped body: `{\"k\": \"v\"}` → unescape the backslash-quotes.
    if (block.includes('\\"') && !/[^\\]"/.test(block.slice(1))) {
      add(unescape(block));
    }
  }

  // Whole-string unescape as a last resort for a double-escaped reply with no
  // recoverable raw block.
  if (trimmed.includes('\\"')) {
    add(unescape(trimmed));
  }

  return out;
}

/** Reverse one layer of string escaping. */
function unescape(text: string): string {
  return text
    .replace(/\\"/g, '"')
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\r/g, "\r")
    .replace(/\\\\/g, "\\");
}

/** The first balanced `{...}` run, respecting string literals and escapes. */
function firstJsonBlock(text: string): string | null {
  const start = text.indexOf("{");
  if (start === -1) {
    return null;
  }
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) {
      continue;
    }
    if (ch === "{") {
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }
  return null;
}
