// ═══════════════════════════════════════════════════════════════
// Cloud API Gateway Handler
// Secure edge routing with rate limiting and request validation
// ═══════════════════════════════════════════════════════════════


// ─────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────

const CONFIG = {
  // Rate limiting (requests per minute)
  rateLimit: {
    perIP: 100,
    perPath: 50,
    blockDuration: 300000, // 5 minutes in ms
  },
  
  // Request validation
  validation: {
    maxBodySize: 10 * 1024 * 1024, // 10MB
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedContentTypes: [
      'application/json',
      'application/x-www-form-urlencoded',
      'multipart/form-data',
      'text/plain',
    ],
  },
  
  // Response masking
  response: {
    defaultContentType: 'application/json',
    apiVersion: '1.0',
    cacheMaxAge: 300, // 5 minutes
  },
};

// ─────────────────────────────────────────────────────────────
// In-memory storage (resets on cold start)
// ─────────────────────────────────────────────────────────────

const rateLimitStore = new Map();
const blockedIPs = new Set();

// ─────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────

function getClientIP(request) {
  return request.headers.get('x-nf-client-connection-ip') ||
         request.headers.get('cf-connecting-ip') ||
         '0.0.0.0';
}

function generateRequestID() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function cleanupRateLimitStore() {
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  
  for (const [key, data] of rateLimitStore.entries()) {
    if (data.timestamp < oneMinuteAgo) {
      rateLimitStore.delete(key);
    }
  }
}

function isBlocked(ip) {
  const blockData = blockedIPs.has(ip);
  if (blockData) {
    const blocked = rateLimitStore.get(`block_${ip}`);
    if (blocked && Date.now() - blocked.timestamp > CONFIG.rateLimit.blockDuration) {
      blockedIPs.delete(ip);
      rateLimitStore.delete(`block_${ip}`);
      return false;
    }
    return true;
  }
  return false;
}

function checkRateLimit(ip, path) {
  cleanupRateLimitStore();
  
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  
  // Check IP-based rate limit
  const ipKey = `ip_${ip}`;
  const ipData = rateLimitStore.get(ipKey) || { count: 0, timestamp: now };
  
  if (ipData.timestamp < oneMinuteAgo) {
    ipData.count = 1;
    ipData.timestamp = now;
  } else {
    ipData.count++;
  }
  
  rateLimitStore.set(ipKey, ipData);
  
  if (ipData.count > CONFIG.rateLimit.perIP) {
    blockedIPs.add(ip);
    rateLimitStore.set(`block_${ip}`, { timestamp: now });
    return { allowed: false, reason: 'ip_limit' };
  }
  
  // Check Path-based rate limit
  const pathKey = `path_${ip}_${path}`;
  const pathData = rateLimitStore.get(pathKey) || { count: 0, timestamp: now };
  
  if (pathData.timestamp < oneMinuteAgo) {
    pathData.count = 1;
    pathData.timestamp = now;
  } else {
    pathData.count++;
  }
  
  rateLimitStore.set(pathKey, pathData);
  
  if (pathData.count > CONFIG.rateLimit.perPath) {
    return { allowed: false, reason: 'path_limit' };
  }
  
  return { allowed: true };
}

function validateRequest(request) {
  const method = request.method;
  const contentType = request.headers.get('content-type') || '';
  
  // Check method
  if (!CONFIG.validation.allowedMethods.includes(method)) {
    return { valid: false, error: 'Method not allowed' };
  }
  
  // Check content-type for POST/PUT/PATCH
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    const isValidContentType = CONFIG.validation.allowedContentTypes.some(
      type => contentType.toLowerCase().includes(type)
    );
    
    if (!isValidContentType && contentType !== '') {
      return { valid: false, error: 'Unsupported content type' };
    }
  }
  
  return { valid: true };
}

function sanitizeHeaders(headers) {
  const sanitized = new Headers();
  
  // Headers to exclude (proxy indicators)
  const excludePatterns = [
    /^x-nf-/i,
    /^x-netlify-/i,
    /^x-forwarded-/i,
    /^x-real-ip$/i,
    /^forwarded$/i,
    /^via$/i,
    /^host$/i,
    /^connection$/i,
    /^keep-alive$/i,
    /^proxy-/i,
    /^te$/i,
    /^trailer$/i,
    /^transfer-encoding$/i,
    /^upgrade$/i,
  ];
  
  // Copy safe headers
  for (const [key, value] of headers.entries()) {
    const shouldExclude = excludePatterns.some(pattern => pattern.test(key));
    if (!shouldExclude) {
      sanitized.set(key, value);
    }
  }
  
  return sanitized;
}

function createNaturalHeaders(requestID) {
  return {
    'X-API-Version': CONFIG.response.apiVersion,
    'X-Request-ID': requestID,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': `public, max-age=${CONFIG.response.cacheMaxAge}`,
    'Vary': 'Accept-Encoding',
  };
}

function maskResponse(upstreamResponse, requestID) {
  const headers = new Headers();
  
  // Add natural headers
  const naturalHeaders = createNaturalHeaders(requestID);
  for (const [key, value] of Object.entries(naturalHeaders)) {
    headers.set(key, value);
  }
  
  // Copy safe upstream headers
  const safeHeaders = ['content-type', 'content-length', 'etag', 'last-modified'];
  for (const header of safeHeaders) {
    const value = upstreamResponse.headers.get(header);
    if (value) {
      headers.set(header, value);
    }
  }
  
  // Force JSON content-type if not set
  if (!headers.has('content-type')) {
    headers.set('content-type', CONFIG.response.defaultContentType);
  }
  
  return headers;
}

function createErrorResponse(status, message, requestID) {
  const body = JSON.stringify({
    status: 'error',
    message: message,
    requestId: requestID,
    timestamp: new Date().toISOString(),
  });
  
  const headers = createNaturalHeaders(requestID);
  headers['Content-Type'] = 'application/json';
  
  return new Response(body, { status, headers });
}

function logRequest(ip, method, path, status, duration, requestID) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    requestId: requestID,
    ip: ip.replace(/\d+$/, 'xxx'), // Mask last octet for privacy
    method,
    path,
    status,
    duration: `${duration}ms`,
  }));
}

// ─────────────────────────────────────────────────────────────
// Main Handler
// ─────────────────────────────────────────────────────────────

export default async (request, context) => {
  const startTime = Date.now();
  const requestID = generateRequestID();
  const clientIP = getClientIP(request);
  const url = new URL(request.url);
  const path = url.pathname;
  
  try {
    // ═══════════════════════════════════════════════════════════
    // 1. Homepage bypass (serve static index.html)
    // ═══════════════════════════════════════════════════════════
    
    if (path === '/') {
      return context.next();
    }
    
    // ═══════════════════════════════════════════════════════════
    // 2. Check if IP is blocked
    // ═══════════════════════════════════════════════════════════
    
    if (isBlocked(clientIP)) {
      logRequest(clientIP, request.method, path, 429, Date.now() - startTime, requestID);
      return createErrorResponse(429, 'Too many requests. Please try again later.', requestID);
    }
    
    // ═══════════════════════════════════════════════════════════
    // 3. Rate limiting
    // ═══════════════════════════════════════════════════════════
    
    const rateLimitResult = checkRateLimit(clientIP, path);
    if (!rateLimitResult.allowed) {
      logRequest(clientIP, request.method, path, 429, Date.now() - startTime, requestID);
      return createErrorResponse(429, 'Rate limit exceeded. Please slow down.', requestID);
    }
    
    // ═══════════════════════════════════════════════════════════
    // 4. Request validation
    // ═══════════════════════════════════════════════════════════
    
    const validation = validateRequest(request);
    if (!validation.valid) {
      logRequest(clientIP, request.method, path, 400, Date.now() - startTime, requestID);
      return createErrorResponse(400, validation.error, requestID);
    }
    
    // ═══════════════════════════════════════════════════════════
    // 5. Get upstream endpoint
    // ═══════════════════════════════════════════════════════════
    
    const dataSource = Netlify.env.get("API_ENDPOINT");
    if (!dataSource) {
      logRequest(clientIP, request.method, path, 503, Date.now() - startTime, requestID);
      return createErrorResponse(503, 'Service temporarily unavailable', requestID);
    }
    
    const upstream = dataSource.replace(/\/+$/, '');
    const targetURL = `${upstream}${path}${url.search}`;
    
    // ═══════════════════════════════════════════════════════════
    // 6. Prepare upstream request
    // ═══════════════════════════════════════════════════════════
    
    const sanitizedHeaders = sanitizeHeaders(request.headers);
    
    const upstreamOptions = {
      method: request.method,
      headers: sanitizedHeaders,
      redirect: 'manual',
    };
    
    // Add body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      upstreamOptions.body = request.body;
    }
    
    // ═══════════════════════════════════════════════════════════
    // 7. Fetch from upstream
    // ═══════════════════════════════════════════════════════════
    
    const upstreamResponse = await fetch(targetURL, upstreamOptions);
    
    // ═══════════════════════════════════════════════════════════
    // 8. Mask and return response
    // ═══════════════════════════════════════════════════════════
    
    const maskedHeaders = maskResponse(upstreamResponse, requestID);
    const duration = Date.now() - startTime;
    
    logRequest(clientIP, request.method, path, upstreamResponse.status, duration, requestID);
    
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: maskedHeaders,
    });
    
  } catch (error) {
    // ═══════════════════════════════════════════════════════════
    // 9. Error handling
    // ═══════════════════════════════════════════════════════════
    
    const duration = Date.now() - startTime;
    logRequest(clientIP, request.method, path, 502, duration, requestID);
    
    return createErrorResponse(502, 'Service temporarily unavailable', requestID);
  }
};
