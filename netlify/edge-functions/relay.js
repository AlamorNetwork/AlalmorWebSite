export default async (request, context) => {
  const url = new URL(request.url);
  const TARGET = Deno.env.get("UPSTREAM_SERVER"); 
  const PORT = Deno.env.get("UPSTREAM_PORT") || "443";
  const AUTH_TOKEN = Deno.env.get("AUTH_TOKEN");

  // اگر درخواست برای صفحه اصلی است، صفحه وب عادی (index.html) را نشان بده (برای ظاهرسازی)
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return context.next();
  }

  if (!TARGET) {
    return new Response("Service Unavailable", { status: 503 });
  }

  // احراز هویت در صورت تنظیم بودن توکن (برای جلوگیری از اسکن شدن توسط ربات‌ها)
  if (AUTH_TOKEN) {
    const clientToken = request.headers.get("x-auth-token") || url.searchParams.get("token");
    if (clientToken !== AUTH_TOKEN) {
      // به جای خطای 401، تظاهر می‌کنیم صفحه پیدا نشد تا پروکسی بودن لو نرود
      return new Response("Not Found", { status: 404 });
    }
  }

  const upstreamUrl = `https://${TARGET}:${PORT}${url.pathname}${url.search}`;
  const headers = new Headers(request.headers);

  // حذف هدرهای خطرناک که پروکسی بودن را لو می‌دهند
  const dropHeaders = [
    "host", "connection", "keep-alive", "te", "trailer", 
    "transfer-encoding", "upgrade", "proxy-connection",
    "x-forwarded-for", "x-real-ip", "x-auth-token"
  ];
  
  dropHeaders.forEach(h => headers.delete(h));

  // حذف هدرهای اختصاصی نتلیفای
  for (const [key, value] of headers.entries()) {
    if (key.toLowerCase().startsWith('x-nf-') || key.toLowerCase().startsWith('x-netlify-')) {
      headers.delete(key);
    }
  }

  // تنظیم هدرهای مرورگر برای عادی جلوه دادن ترافیک
  if (!headers.has("user-agent")) {
    headers.set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  }

  try {
    const response = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual"
    });

    const responseHeaders = new Headers(response.headers);
    responseHeaders.delete("strict-transport-security"); // جلوگیری از مشکلات HSTS

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    // در صورت قطعی سرور شما، خطای 404 برمی‌گردانیم تا ساختار شبکه لو نرود
    return new Response("Not Found", { status: 404 });
  }
};
