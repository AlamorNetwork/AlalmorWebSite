export default async (request, context) => {
  // خواندن متغیرهای محیطی
  const UPSTREAM_SERVER = Deno.env.get("UPSTREAM_SERVER");
  const UPSTREAM_PORT = Deno.env.get("UPSTREAM_PORT") || "443";
  const AUTH_TOKEN = Deno.env.get("AUTH_TOKEN");

  const url = new URL(request.url);

  // ۱. عبور دادن درخواست‌های صفحه اصلی تا سایت طبیعی به نظر برسد
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return context.next();
  }

  // ۲. احراز هویت مخفیانه (اگر توکن اشتباه بود خطای 404 میدهد تا پروکسی بودن لو نرود)
  if (AUTH_TOKEN) {
    const token = request.headers.get("x-auth-token") || url.searchParams.get("token");
    if (token !== AUTH_TOKEN) {
      return new Response(JSON.stringify({ error: "Not Found" }), { 
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  if (!UPSTREAM_SERVER) {
    // خطای فرمت API برای گمراه کردن مانیتورینگ
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
    });
  }

  const targetUrl = `https://${UPSTREAM_SERVER}:${UPSTREAM_PORT}${url.pathname}${url.search}`;

  // ۳. پاکسازی هدرهای درخواست (مخفی کردن ردپای نتلیفای از سرور شما)
  const headers = new Headers(request.headers);
  const headersToRemove = [
    "host", "x-forwarded-for", "x-real-ip", "x-nf-client-connection-ip",
    "x-netlify-edge", "x-nf-request-id", "x-auth-token"
  ];
  
  for (const key of headers.keys()) {
    if (key.startsWith("x-nf-") || key.startsWith("x-netlify-") || headersToRemove.includes(key.toLowerCase())) {
      headers.delete(key);
    }
  }

  // اضافه کردن یک User-Agent معتبر اگر وجود نداشت
  if (!headers.has("user-agent")) {
    headers.set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  }

  try {
    const fetchOptions = {
      method: request.method,
      headers: headers,
      redirect: "manual",
    };

    if (request.method !== "GET" && request.method !== "HEAD") {
      fetchOptions.body = request.body;
    }

    // ۴. ارسال درخواست به سرور شما
    const response = await fetch(targetUrl, fetchOptions);

    // ۵. پاکسازی هدرهای پاسخ (مخفی کردن ردپای سرور شما از نتلیفای)
    const responseHeaders = new Headers(response.headers);
    const resHeadersToRemove = [
      "strict-transport-security",
      "x-powered-by", // مخفی کردن تکنولوژی سرور شما
      "server"        // اجازه می‌دهیم netlify.toml هدر سرور جعلی (cloudflare) را ست کند
    ];
    resHeadersToRemove.forEach(h => responseHeaders.delete(h));

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    // ۶. استتار قطعی سرور به عنوان یک خطای تایم‌اوت API استاندارد
    return new Response(JSON.stringify({ message: "Gateway Timeout", code: 504 }), {
      status: 504,
      headers: { "Content-Type": "application/json" }
    });
  }
};
