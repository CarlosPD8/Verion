// CLAUDE.md rule 12 for frontend/, the module that handles the access token.
// ADR-0031 decision 1 holds the token in memory only; these tests make that a claim
// rather than a comment. Node's built-in runner with type stripping, so no test
// dependency outside ADR-0031 decision 3's list:
//   npm test   (node --experimental-strip-types --test "tests/*.test.mjs")
// Not run in CI (G69).

import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { fetchScoredRisks, login } from "../lib/api.ts";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const SOURCE_DIRS = ["app", "lib"];
const TOKEN = "eyJhbGciOiJIUzI1NiJ9.LEAK-PROBE.token-value";

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      return sourceFiles(path);
    }
    return /\.(tsx?|mjs|js)$/.test(name) ? [path] : [];
  });
}

test("no source file persists or prints anything: no Web Storage, cookie, IndexedDB or console", () => {
  const files = SOURCE_DIRS.flatMap((dir) => sourceFiles(join(ROOT, dir)));
  assert.ok(files.length >= 4, `expected the screen's sources, found ${files.length}`);
  // Keyed on USE (`localStorage.`), not on the word: session.ts's own comment names the
  // storage it refuses, and a word match would fail on the sentence that documents the rule.
  const forbidden = /\b(localStorage|sessionStorage|indexedDB|console)\s*\.|document\s*\.\s*cookie/;
  const offenders = files.filter((file) => forbidden.test(readFileSync(file, "utf8")));
  assert.deepEqual(offenders, []);
});

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function stubFetch(respond) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return respond();
  };
  return calls;
}

for (const [label, respond] of [
  ["401", () => new Response(JSON.stringify({ detail: "Invalid or expired token" }), { status: 401 })],
  ["404", () => new Response(JSON.stringify({ detail: "No readable project" }), { status: 404 })],
  ["500", () => new Response(JSON.stringify({ detail: TOKEN }), { status: 500 })],
  ["network failure", () => Promise.reject(new Error(`boom ${TOKEN}`))],
]) {
  test(`a failed scored-risks read (${label}) returns a result that carries no token`, async () => {
    const calls = stubFetch(respond);
    const result = await fetchScoredRisks(TOKEN, "project-1", 0);
    assert.notEqual(result.kind, "ok");
    assert.equal(JSON.stringify(result).includes(TOKEN), false);
    assert.equal(calls.length, 1);
    // The token travels in the Authorization header only, never in the URL, and only
    // to this origin's /api/* rewrite (ADR-0031 decision 2).
    assert.equal(calls[0].url.startsWith("/api/"), true);
    assert.equal(calls[0].url.includes(TOKEN), false);
    assert.equal(calls[0].init.headers.Authorization, `Bearer ${TOKEN}`);
  });
}

test("a failed login returns a result that carries no token", async () => {
  stubFetch(() => new Response(JSON.stringify({ access_token: TOKEN }), { status: 500 }));
  const result = await login("user@example.test", "password");
  assert.deepEqual(result, { kind: "error" });
});
