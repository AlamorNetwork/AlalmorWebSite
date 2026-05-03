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
  }

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
  }
};
