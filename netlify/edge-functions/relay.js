<<<<<<< HEAD
export default async (request, context) => {
  const upstreamServer = Netlify.env.get("UPSTREAM_SERVER");
  const upstreamPort = Netlify.env.get("UPSTREAM_PORT");
  const authToken = Netlify.env.get("AUTH_TOKEN");

  if (!upstreamServer || !upstreamPort) {
    return new Response("Configuration error", { status: 500 });
  }

  const url = new URL(request.url);

  // Bypass root path
  if (url.pathname === "/") {
    return context.next();
  }

  // Build upstream URL
  const upstreamUrl = `https://${upstreamServer}:${upstreamPort}${url.pathname}${url.search}`;

  // Filter headers
  const excludedHeaders = new Set([
    "host",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-nf-request-id",
    "x-nf-client-connection-ip"
  ]);

  const headers = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (!excludedHeaders.has(key.toLowerCase())) {
      headers.set(key, value);
    }
=======
const TARGET = Netlify.env.get("UPSTREAM_SERVER");
const PORT = Netlify.env.get("UPSTREAM_PORT") || "50592";
const AUTH_TOKEN = Netlify.env.get("AUTH_TOKEN");
const MAX_REQUESTS_PER_MINUTE = 60;

// In-memory rate limiter (per IP)
const rateLimiter = new Map();

const STRIP_HEADERS = new Set([
  "host", "connection", "keep-alive", "te", "trailer",
  "transfer-encoding", "upgrade", "proxy-connection",
  "proxy-authenticate", "proxy-authorization"
]);

const NETLIFY_HEADERS = /^x-(nf|netlify)-/i;

// Mimic normal browser traffic
const SAFE_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
];

function checkRateLimit(ip) {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const key = `${ip}:${minute}`;
  
  const count = rateLimiter.get(key) || 0;
  if (count >= MAX_REQUESTS_PER_MINUTE) {
    return false;
  }
  
  rateLimiter.set(key, count + 1);
  
  // Cleanup old entries
  if (rateLimiter.size > 1000) {
    const oldMinute = minute - 2;
    for (const [k] of rateLimiter) {
      if (k.endsWith(`:${oldMinute}`)) {
        rateLimiter.delete(k);
      }
    }
  }
  
  return true;
}

function validateRequest(req, url) {
  // Block suspicious paths
  const suspiciousPaths = [
    "/admin", "/wp-admin", "/.env", "/.git",
    "/config", "/backup", "/phpmyadmin"
  ];
  
  if (suspiciousPaths.some(p => url.pathname.startsWith(p))) {
    return { valid: false, reason: "Invalid path" };
  }
  
  // Require auth token if configured
  if (AUTH_TOKEN) {
    const token = req.headers.get("x-auth-token") || 
                  url.searchParams.get("token");
    if (token !== AUTH_TOKEN) {
      return { valid: false, reason: "Unauthorized" };
    }
>>>>>>> cc42b11771dd9f7af332dd3d6d92235f5ba0058e
  }
  
  return { valid: true };
}

<<<<<<< HEAD
  // Add auth token if exists
  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }

  try {
    const upstreamResponse = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      redirect: "manual"
    });

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: upstreamResponse.headers
    });
  } catch (error) {
    return new Response("Service unavailable", { status: 502 });
=======
export default async (req, ctx) => {
  const url = new URL(req.url);
  
  // Serve static root
  if (url.pathname === "/") {
    return ctx.next();
  }
  
  // Get client IP
  const clientIP = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
                   req.headers.get("x-real-ip") ||
                   ctx.ip ||
                   "unknown";
  
  // Rate limiting
  if (!checkRateLimit(clientIP)) {
    return new Response("Too many requests", { 
      status: 429,
      headers: { "Retry-After": "60" }
    });
>>>>>>> cc42b11771dd9f7af332dd3d6d92235f5ba0058e
  }
  
  // Validate request
  const validation = validateRequest(req, url);
  if (!validation.valid) {
    return new Response(validation.reason, { status: 403 });
  }
  
  if (!TARGET) {
    return new Response("Service unavailable", { status: 503 });
  }
  
  // Build upstream URL
  const upstream = `${TARGET}:${PORT}${url.pathname}${url.search}`;
  
  // Prepare headers
  const headers = new Headers();
  for (const [key, value] of req.headers) {
    const lower = key.toLowerCase();
    if (!STRIP_HEADERS.has(lower) && !NETLIFY_HEADERS.test(key)) {
      headers.set(key, value);
    }
  }
  
  // Remove auth token from forwarded headers
  headers.delete("x-auth-token");
  
  // Set realistic User-Agent if missing
  if (!headers.has("user-agent")) {
    const randomUA = SAFE_USER_AGENTS[
      Math.floor(Math.random() * SAFE_USER_AGENTS.length)
    ];
    headers.set("user-agent", randomUA);
  }
  
  // Preserve client IP
  headers.set("x-forwarded-for", clientIP);
  headers.set("x-real-ip
