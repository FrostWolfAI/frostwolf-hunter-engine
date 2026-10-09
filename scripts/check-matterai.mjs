#!/usr/bin/env node
/**
 * Confirm MATTERAI_API_KEY and MATTERAI_BASE_URL actually work, and that the
 * response matches the OpenAI chat-completions shape `src/models/matterai.ts`
 * assumes, before trusting either in a real hunt.
 *
 * Usage:
 *   node scripts/check-matterai.mjs [model]
 *
 * Reads MATTERAI_API_KEY / MATTERAI_BASE_URL / ATTACKER_MODEL from `.env` in
 * this directory (no dependency — a tiny inline parser), or from the real
 * environment if already exported.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnv(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (process.env[key] === undefined && value.length > 0) {
      process.env[key] = value;
    }
  }
}

loadDotEnv(resolve(process.cwd(), ".env"));

const baseUrl = (process.env.MATTERAI_BASE_URL ?? "https://api2.matterai.so/v1").replace(/\/$/, "");
const apiKey = process.env.MATTERAI_API_KEY ?? "";
const model = process.argv[2] ?? process.env.ATTACKER_MODEL ?? "glm-5.3";

if (apiKey.length === 0) {
  console.error("MATTERAI_API_KEY is not set (checked .env and the environment).");
  process.exit(1);
}

console.log(`POST ${baseUrl}/chat/completions  model=${model}`);

const response = await fetch(`${baseUrl}/chat/completions`, {
  method: "POST",
  headers: {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
  },
  body: JSON.stringify({
    model,
    messages: [{ role: "user", content: 'Reply with exactly the word: ok' }],
    temperature: 0,
  }),
});

const text = await response.text();
console.log(`status: ${response.status}`);

if (!response.ok) {
  console.error("Request failed. Body:");
  console.error(text.slice(0, 2000));
  process.exit(1);
}

let body;
try {
  body = JSON.parse(text);
} catch {
  console.error("Response was not JSON. This does not match the OpenAI chat-completions shape");
  console.error("src/models/matterai.ts assumes — update that file to match. Raw body:");
  console.error(text.slice(0, 2000));
  process.exit(1);
}

const content = body?.choices?.[0]?.message?.content;
if (typeof content !== "string") {
  console.error("Response was JSON but did not carry choices[0].message.content — the shape");
  console.error("src/models/matterai.ts assumes does not match. Full body:");
  console.error(JSON.stringify(body, null, 2));
  process.exit(1);
}

console.log(`model replied: ${JSON.stringify(content)}`);
console.log(`usage.total_tokens: ${body?.usage?.total_tokens ?? "(not reported)"}`);
console.log("\nmatterai.so client contract confirmed.");
