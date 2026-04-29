// نام متغیر محیطی تغییر کرده است
const UPSTREAM_URL = Netlify.env.get("PROXY_TARGET")?.replace(/\/+$/, "");

// تغییر نام و ساختار لیست هدرهای مسدود شده
const EXCLUDED_HEADERS = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding",
  "upgrade", "forwarded", "x-forwarded-host",
  "x-forwarded-proto", "x-forwarded-port"
]);

export default async (request) => {
  // تغییر پیام خطای 500
  if (!UPSTREAM_URL) {
    return new Response("System Error: PROXY_TARGET is missing in environment.", { status: 500 });
  }

  const currentUrl = new URL(request.url);
  const destination = UPSTREAM_URL + currentUrl.pathname + currentUrl.search;

  const proxyHeaders = new Headers();
  let userIp = "";

  // تغییر منطق کپی کردن هدرها
  for (const [headerName, headerValue] of request.headers.entries()) {
    const key = headerName.toLowerCase();
    
    if (EXCLUDED_HEADERS.has(key) || key.startsWith("x-nf-") || key.startsWith("x-netlify-")) {
      continue;
    }
    
    if (key === "x-real-ip" || key === "x-forwarded-for") {
      userIp = headerValue;
    }
    
    proxyHeaders.set(headerName, headerValue);
  }

  if (userIp) {
    proxyHeaders.set("x-forwarded-for", userIp);
  }

  const fetchOptions = {
    method: request.method,
    headers: proxyHeaders,
    redirect: "manual"
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    fetchOptions.body = request.body;
  }

  try {
    const response = await fetch(destination, fetchOptions);
    const responseHeaders = new Headers(response.headers);
    responseHeaders.delete("transfer-encoding");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    // تغییر پیام خطای 502
    return new Response("Gateway Error: Upstream connection failed.", { status: 502 });
  }
};
