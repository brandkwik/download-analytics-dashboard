const REPORT_URL = "https://xyuevtnocfgdlvfzlmub.supabase.co/functions/v1/download-analytics-report";
const COOKIE = "analytics_session";
const SESSION_SECONDS = 8 * 60 * 60;
const attempts = new Map();

const encoder = new TextEncoder();

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(left, right) {
  const length = Math.max(left.length, right.length);
  let different = left.length ^ right.length;
  for (let index = 0; index < length; index++) {
    different |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return different === 0;
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

async function passwordHash(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", hash: "SHA-256", salt: Uint8Array.from(salt.match(/.{2}/g), (part) => parseInt(part, 16)), iterations,
  }, key, 256);
  return hex(new Uint8Array(bits));
}

function cookieValue(request) {
  const header = request.headers.get("cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return match ? match[1] : "";
}

async function session(request, env) {
  try {
    const [payload, signature] = cookieValue(request).split(".");
    if (!payload || !signature || !constantTimeEqual(signature, await hmac(payload, env.SESSION_SIGNING_KEY))) return null;
    const value = JSON.parse(new TextDecoder().decode(fromBase64url(payload)));
    return value.email && Number(value.expires) > Date.now() ? value.email : null;
  } catch {
    return null;
  }
}

function response(payload, status = 200, cookie = "") {
  const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
  if (cookie) headers["set-cookie"] = cookie;
  return new Response(JSON.stringify(payload), { status, headers });
}

async function login(request, env) {
  const client = request.headers.get("cf-connecting-ip") || "unknown";
  const now = Date.now();
  const recent = (attempts.get(client) || []).filter((stamp) => now - stamp < 15 * 60 * 1000);
  attempts.set(client, recent);
  if (recent.length >= 5) return response({ error: "Too many attempts. Try again in 15 minutes." }, 429);
  try {
    const input = await request.json();
    const config = JSON.parse(env.DASHBOARD_AUTH_JSON);
    const email = String(input.email || "").trim().toLowerCase();
    const candidate = await passwordHash(String(input.password || ""), config.salt, Number(config.iterations));
    if (!constantTimeEqual(email, String(config.email).toLowerCase()) || !constantTimeEqual(candidate, config.password_hash)) throw new Error("invalid");
    attempts.delete(client);
    const payload = base64url(encoder.encode(JSON.stringify({ email, expires: now + SESSION_SECONDS * 1000 })));
    const signed = `${payload}.${await hmac(payload, env.SESSION_SIGNING_KEY)}`;
    return response({ authenticated: true, email }, 200,
      `${COOKIE}=${signed}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`);
  } catch {
    recent.push(now);
    attempts.set(client, recent);
    return response({ error: "Incorrect email or password." }, 401);
  }
}

async function handleApi(request, env, url) {
  if (url.pathname === "/api/login" && request.method === "POST") return login(request, env);
  if (url.pathname === "/api/logout" && request.method === "POST") {
    return response({ authenticated: false }, 200, `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
  }
  const email = await session(request, env);
  if (url.pathname === "/api/session" && request.method === "GET") {
    return response({ authenticated: !!email, email }, email ? 200 : 401);
  }
  if (url.pathname === "/api/report" && request.method === "GET") {
    if (!email) return response({ error: "login_required" }, 401);
    const target = new URL(REPORT_URL);
    target.search = url.search;
    const upstream = await fetch(target, { headers: { Authorization: `Bearer ${env.ANALYTICS_DASHBOARD_TOKEN}` } });
    return new Response(upstream.body, { status: upstream.status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  }
  return response({ error: "not_found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return handleApi(request, env, url);
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("x-content-type-options", "nosniff");
    headers.set("x-frame-options", "DENY");
    headers.set("content-security-policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers });
  },
};
