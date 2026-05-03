// ═══════════════════════════════════════════════════════════════
// NexGen Cloud Relay - Advanced Edge Gateway
// Professional proxy with security, rate limiting & monitoring
// ═══════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────
// Configuration & Constants
// ─────────────────────────────────────────────────────────────

const CONFIG = {
  // Rate Limiting
  rateLimit: {
    windowMs: 60000,        // 1 minute window
    maxRequests: 100,       // 100 requests per minute per IP
    blockDuration: 300000   // 5 minutes block
  },
  
  // Request Validation
  validation: {
    maxBodySize: 10485760,  // 10MB
    maxUrlLength: 2048,
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    blockedPaths: ['/admin', '/.env', '/.git', '/config'],
    suspiciousPatterns: [
      /\.\.\//g,            // Path traversal
      /<script/gi,          // XSS attempts
      /union.*select/gi,    // SQL injection
      /javascript:/gi       // JS injection
    ]
  },
  
  // Security Headers
  security: {
    removeHeaders: [
      'x-powered-by',
      'server',
      'x-aspnet-version',
      'x-aspnetmvc-version'
    ],
    addHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
  },
  
  // Proxy Settings
  proxy: {
    timeout: 30000,         // 30 seconds
    retries: 2,
    retryDelay: 1000
  }
};

// ─────────────────────────────────────────────────────────────
// In-Memory Storage (Edge Function Scope)
// ─────────────────────────────────────────────────────────────

const rateLimitStore = new Map();
const blockedIPs = new Map();
const requestStats = {
  total: 0,
  blocked: 0,
  proxied: 0,
  errors: 0
};

// ─────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────

function getClientIP(request) {
  return request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
         request.headers.get('cf-connecting-ip') ||
         request.headers.get('x-real-ip') ||
         'unknown';
}

function cleanupExpiredEntries() {
  const now = Date.now();
  
  // Cleanup rate limit store
  for (const [key, data] of rateLimitStore.entries()) {
    if (now - data.resetTime > CONFIG.rateLimit.windowMs) {
      rateLimitStore.delete(key);
    }
  }
  
  // Cleanup blocked IPs
  for (const [ip, blockTime] of blockedIPs.entries()) {
    if (now - blockTime > CONFIG.rateLimit.blockDuration) {
      blockedIPs.delete(ip);
    }
  }
}

function checkRateLimit(ip) {
  const now = Date.now();
  const key = `ratelimit:${ip}`;
  
  // Check if IP is blocked
  if (blockedIPs.has(ip)) {
    const blockTime = blockedIPs.get(ip);
    if (now - blockTime < CONFIG.rateLimit.blockDuration) {
      return {
        allowed: false,
        reason: 'IP temporarily blocked',
        retryAfter: Math.ceil((CONFIG.rateLimit.blockDuration - (now - blockTime)) / 1000)
      };
    }
    blockedIPs.delete(ip);
  }
  
  // Get or create rate limit entry
  let limitData = rateLimitStore.get(key);
  
  if (!limitData || now - limitData.resetTime > CONFIG.rateLimit.windowMs) {
    limitData = {
      count: 0,
      resetTime: now
    };
  }
  
  limitData.count++;
  rateLimitStore.set(key, limitData);
  
  // Check if limit exceeded
  if (limitData.count > CONFIG.rateLimit.maxRequests) {
    blockedIPs.set(ip, now);
    return {
      allowed: false,
      reason: 'Rate limit exceeded',
      retryAfter: Math.ceil(CONFIG.rateLimit.blockDuration / 1000)
    };
  }
  
  return {
    allowed: true,
    remaining: CONFIG.rateLimit.maxRequests - limitData.count,
    resetTime: limitData.resetTime + CONFIG.rateLimit.windowMs
  };
}

function validateRequest(request, url) {
  const errors = [];
  
  // Method validation
  if (!CONFIG.validation.allowedMethods.includes(request.method)) {
    errors.push(`Method ${request.method} not allowed`);
  }
  
  // URL length validation
  if (url.href.length > CONFIG.validation.maxUrlLength) {
    errors.push('URL too long');
  }
  
  // Path validation
  const pathname = url.pathname.toLowerCase();
  for (const blocked of CONFIG.validation.blockedPaths) {
    if (pathname.startsWith(blocked)) {
      errors.push(`Access to ${blocked} is forbidden`);
    }
  }
  
  // Suspicious pattern detection
  const fullUrl = url.href;
  for (const pattern of CONFIG.validation.suspiciousPatterns) {
    if (pattern.test(fullUrl)) {
      errors.push('Suspicious pattern detected');
      break;
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

function sanitizeHeaders(headers, isRequest = true) {
  const sanitized = new Headers();
  
  // Excluded headers (hop-by-hop & Netlify-specific)
  const excluded = new Set([
    'host',
    'connection',
    'keep-alive',
    'transfer-encoding',
    'upgrade',
    'proxy-connection',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-nf-request-id',
    'x-nf-client-connection-ip'
  ]);
  
  for (const [key, value] of headers.entries()) {
    const lowerKey = key.toLowerCase();
    
    if (!excluded.has(lowerKey)) {
      // Remove security-sensitive headers from responses
      if (!isRequest && CONFIG.security.removeHeaders.includes(lowerKey)) {
        continue;
      }
      sanitized.set(key, value);
    }
  }
  
  return sanitized;
}

function createErrorResponse(status, message, details = {}) {
  return new Response(
    JSON.stringify({
      error: true,
      status,
      message,
      timestamp: new Date().toISOString(),
      ...details
    }),
    {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...CONFIG.security.addHeaders
      }
    }
  );
}

async function proxyRequest(request, upstreamUrl) {
  const url = new URL(request.url);
  const destination = upstreamUrl + url.pathname + url.search;
  
  // Prepare headers
  const headers = sanitizeHeaders(request.headers, true);
  
  // Add forwarding headers
  const clientIP = getClientIP(request);
  headers.set('X-Forwarded-For', clientIP);
  headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
  headers.set('X-Real-IP', clientIP);
  
  // Retry logic
  let lastError;
  for (let attempt = 0; attempt <= CONFIG.proxy.retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONFIG.proxy.timeout);
      
      const response = await fetch(destination, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        redirect: 'manual',
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      // Sanitize response headers
      const responseHeaders = sanitizeHeaders(response.headers, false);
      
      // Add security headers
      for (const [key, value] of Object.entries(CONFIG.security.addHeaders)) {
        responseHeaders.set(key, value);
      }
      
      // Add custom headers
      responseHeaders.set('X-Proxy-Status', 'success');
      responseHeaders.set('X-Upstream-Status', response.status.toString());
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });
      
    } catch (error) {
      lastError = error;
      
      if (attempt < CONFIG.proxy.retries) {
        await new Promise(resolve => setTimeout(resolve, CONFIG.proxy.retryDelay * (attempt + 1)));
      }
    }
  }
  
  // All retries failed
  requestStats.errors++;
  throw lastError;
}

// ─────────────────────────────────────────────────────────────
// Main Edge Function Handler
// ─────────────────────────────────────────────────────────────

export default async (request, context) => {
  const startTime = Date.now();
  const url = new URL(request.url);
  const clientIP = getClientIP(request);
  
  requestStats.total++;
  
  // Periodic cleanup
  if (requestStats.total % 100 === 0) {
    cleanupExpiredEntries();
  }
  
  try {
    // ─────────────────────────────────────────────────────────
    // 1. Homepage bypass (serve static content)
    // ─────────────────────────────────────────────────────────
    
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return context.next();
    }
    
    // ─────────────────────────────────────────────────────────
    // 2. Rate Limiting
    // ─────────────────────────────────────────────────────────
    
    const rateLimitResult = checkRateLimit(clientIP);
    
    if (!rateLimitResult.allowed) {
      requestStats.blocked++;
      return createErrorResponse(429, rateLimitResult.reason, {
        retryAfter: rateLimitResult.retryAfter,
        clientIP
      });
    }
    
    // ─────────────────────────────────────────────────────────
    // 3. Request Validation
    // ─────────────────────────────────────────────────────────
    
    const validation = validateRequest(request, url);
    
    if (!validation.valid) {
      requestStats.blocked++;
      return createErrorResponse(400, 'Invalid request', {
        errors: validation.errors,
        clientIP
      });
    }
    
    // ─────────────────────────────────────────────────────────
    // 4. Get Upstream Target
    // ─────────────────────────────────────────────────────────
    
    const upstreamUrl = Netlify.env.get('PROXY_TARGET');
    
    if (!upstreamUrl) {
      return createErrorResponse(500, 'Proxy target not configured');
    }
    
    const cleanUpstream = upstreamUrl.replace(/\/+$/, '');
    
    // ─────────────────────────────────────────────────────────
    // 5. Proxy Request
    // ─────────────────────────────────────────────────────────
    
    const response = await proxyRequest(request, cleanUpstream);
    
    requestStats.proxied++;
    
    // Add performance headers
    const duration = Date.now() - startTime;
    response.headers.set('X-Response-Time', `${duration}ms`);
    response.headers.set('X-Rate-Limit-Remaining', rateLimitResult.remaining.toString());
    response.headers.set('X-Rate-Limit-Reset', new Date(rateLimitResult.resetTime).toISOString());
    
    return response;
    
  } catch (error) {
    requestStats.errors++;
    
    console.error('Relay error:', {
      message: error.message,
      clientIP,
      path: url.pathname,
      method: request.method
    });
    
    return createErrorResponse(502, 'Upstream service unavailable', {
      reason: error.message,
      clientIP
    });
  }
};

// ─────────────────────────────────────────────────────────────
// Health Check & Stats Endpoint (Optional)
// ─────────────────────────────────────────────────────────────

export const config = {
  path: "/*",
  excludedPath: "/health"
};
