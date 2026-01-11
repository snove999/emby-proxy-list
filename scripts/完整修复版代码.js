const DEFAULT_CONFIG = {
  BLOCKED_UPSTREAMS: ['google.com','googleapis.com','gstatic.com','facebook.com','twitter.com','x.com','paypal.com','stripe.com','alipay.com','cloudflare.com','amazonaws.com','azure.com'],
  DIRECT_REDIRECT_DOMAINS: ['quark.cn','uc.cn','115.com','115cdn.com','115cdn.net','aliyundrive.com','aliyundrive.net','189.cn','ctyunxs.cn','mini189.cn','telecomjs.com','xunlei.com','voicehub.top','xiaoya.pro'],
  ALLOWED_UPSTREAMS: [],
  MEDIA_PATH_PATTERNS: ['/emby/','/jellyfin/','/mediabrowser/','/Videos/','/Audio/','/Items/','/Users/','/Sessions/','/System/','/Library/','/PlaybackInfo','/Playing','/socket','/embywebsocket'],
  STREAM_PATTERNS: ['/stream','.m3u8','.ts','.mp4','.mkv','.webm','.mp3','.flac','.aac','.wav'],
  HEADERS_TO_REMOVE: ['content-security-policy','content-security-policy-report-only','x-frame-options'],
  HEADERS_TO_SKIP: ['host','cf-connecting-ip','cf-ipcountry','cf-ray','cf-visitor','cf-ew-via','cdn-loop','cf-worker'],
  AUTO_REWRITE_ENABLED: true,
  AUTO_PROXY_PATTERNS: ['*.sharepoint.cn','*.sharepoint.com','*.emosstore.sbs','*.onedrive.com','*.blob.core.windows.net','*.blob.core.chinacloudapi.cn'],
  REWRITABLE_CONTENT_TYPES: ['text/html','application/json','application/javascript','text/javascript','application/xml','text/xml','application/x-mpegurl','application/vnd.apple.mpegurl'],
  BLOCKED_USER_AGENTS: ['curl','wget','python','scrapy','bot','spider','crawler','go-http-client'],
  ENABLE_BOT_PROTECTION: false,
  BLOCK_EMPTY_UA: false,
  ENABLE_WHITELIST: false,
  PROTOCOL_CACHE_TTL: 86400,
  PROBE_TIMEOUT: 5000,
  MAX_PROTO_CACHE_SIZE: 1000,
  CONFIG_CACHE_TTL: 300000,
};

let runtimeConfig = null;
let configLoadedAt = 0;

class LRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) return undefined;
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.cache.has(key)) this.cache.delete(key);
    else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  has(key) {
    return this.cache.has(key);
  }

  get size() {
    return this.cache.size;
  }
}

const protocolCache = new LRUCache(DEFAULT_CONFIG.MAX_PROTO_CACHE_SIZE);

export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    try {
      const config = await loadConfig(env);
      const context = buildContext(request, env, config);
      const response = await route(context, ctx);
      return finalize(response, startTime, context);
    } catch (error) {
      console.error('[Fatal]', error.stack || error.message);
      return json({ error: 'Internal error', message: error.message }, 500);
    }
  },
};

async function loadConfig(env) {
  const cacheTTL = DEFAULT_CONFIG.CONFIG_CACHE_TTL;
  if (runtimeConfig && Date.now() - configLoadedAt < cacheTTL) return runtimeConfig;

  const config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  
  config.ENABLE_WHITELIST = env.ENABLE_WHITELIST === 'true';
  config.PROTOCOL_CACHE_TTL = parseInt(env.PROTOCOL_CACHE_TTL || '86400', 10);
  config.AUTO_REWRITE_ENABLED = env.AUTO_REWRITE_ENABLED !== 'false';
  config.ENABLE_BOT_PROTECTION = env.ENABLE_BOT_PROTECTION === 'true';
  config.BLOCK_EMPTY_UA = env.BLOCK_EMPTY_UA === 'true';

  if (env.PROBE_TIMEOUT) config.PROBE_TIMEOUT = parseInt(env.PROBE_TIMEOUT, 10);
  if (env.MAX_PROTO_CACHE_SIZE) config.MAX_PROTO_CACHE_SIZE = parseInt(env.MAX_PROTO_CACHE_SIZE, 10);

  if (env.PROXY_KV) {
    try {
      const [blocked, direct, allowed, autoProxy] = await Promise.all([
        env.PROXY_KV.get('config:blocked_upstreams', { type: 'json' }),
        env.PROXY_KV.get('config:direct_redirect_domains', { type: 'json' }),
        env.PROXY_KV.get('config:allowed_upstreams', { type: 'json' }),
        env.PROXY_KV.get('config:auto_proxy_patterns', { type: 'json' }),
      ]);
      if (blocked && blocked.length) config.BLOCKED_UPSTREAMS = blocked;
      if (direct && direct.length) config.DIRECT_REDIRECT_DOMAINS = direct;
      if (allowed && allowed.length) config.ALLOWED_UPSTREAMS = allowed;
      if (autoProxy && autoProxy.length) config.AUTO_PROXY_PATTERNS = autoProxy;
    } catch (e) {
      console.error('[Config] KV load failed:', e.message);
    }
  }

  config._autoProxyRegexes = config.AUTO_PROXY_PATTERNS.map(function(pattern) {
    const escaped = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[a-zA-Z0-9-]+');
    return new RegExp('^' + escaped + '$', 'i');
  });

  config._rewritableTypeSet = new Set(
    config.REWRITABLE_CONTENT_TYPES.map(function(t) { return t.toLowerCase(); })
  );

  runtimeConfig = config;
  configLoadedAt = Date.now();
  return config;
}

function buildContext(request, env, config) {
  const url = new URL(request.url);
  const cf = request.cf || {};
  return {
    request: request,
    env: env,
    url: url,
    config: config,
    clientIP: request.headers.get('cf-connecting-ip') || 'unknown',
    clientCountry: cf.country || 'XX',
    edgeColo: cf.colo || 'unknown',
    isWebSocket: (request.headers.get('upgrade') || '').toLowerCase() === 'websocket',
    primaryHost: null,
  };
}

async function route(ctx, waitCtx) {
  const url = ctx.url;
  const request = ctx.request;
  const isWebSocket = ctx.isWebSocket;
  const config = ctx.config;
  const path = url.pathname;

  if (config.ENABLE_BOT_PROTECTION) {
    const botCheck = checkBot(request, config);
    if (botCheck) return botCheck;
  }

  if (path === '/') return statusPage(ctx);
  if (path === '/health') return new Response('OK', { headers: { 'Content-Type': 'text/plain' } });
  if (request.method === 'OPTIONS') return cors(request);

  const target = parseUrl(url);
  if (!target) return json({ error: 'Invalid URL format' }, 400);

  const access = checkAccess(target.hostname, config);
  if (!access.ok) return json({ error: access.reason, domain: target.hostname }, 403);

  const protocol = await resolveProtocol(target.hostname, target.port, target.userProtocol, ctx.env, config);
  ctx.primaryHost = target.hostname;

  waitCtx.waitUntil(recordStats(ctx, target).catch(function(e) { console.error('[Stats Error]', e.message); }));

  return isWebSocket ? handleWS(ctx, target, protocol) : handleHTTP(ctx, target, protocol);
}

function parseUrl(workerUrl) {
  let path = workerUrl.pathname.slice(1);
  if (!path) return null;

  let userProtocol = null;
  const protocolPrefixes = ['https://', 'http://', 'https/', 'http/'];
  for (let i = 0; i < protocolPrefixes.length; i++) {
    const prefix = protocolPrefixes[i];
    if (path.startsWith(prefix)) {
      userProtocol = prefix.startsWith('https') ? 'https' : 'http';
      path = path.slice(prefix.length);
      break;
    }
  }

  const slashIdx = path.indexOf('/');
  const host = slashIdx === -1 ? path : path.substring(0, slashIdx);
  const remainPath = slashIdx === -1 ? '/' : path.substring(slashIdx);

  const bracketIdx = host.indexOf(']');
  const colonIdx = bracketIdx !== -1 ? host.indexOf(':', bracketIdx) : host.lastIndexOf(':');

  let hostname = null;
  let port = null;
  if (colonIdx > 0) {
    hostname = host.substring(0, colonIdx);
    const portStr = host.substring(colonIdx + 1);
    port = parseInt(portStr, 10);
    if (isNaN(port) || port < 1 || port > 65535) port = null;
  } else {
    hostname = host;
  }

  if (hostname && hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1);
  }

  if (!hostname || !isValidHost(hostname)) return null;

  return {
    userProtocol: userProtocol,
    host: host,
    hostname: hostname,
    port: port,
    path: remainPath,
    search: workerUrl.search,
    fullPath: remainPath + workerUrl.search,
  };
}

function isValidHost(h) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    const parts = h.split('.');
    for (let i = 0; i < parts.length; i++) {
      const n = parseInt(parts[i], 10);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }
  if (/^[a-f0-9:]+$/i.test(h) && h.includes(':')) return true;
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(h);
}

function checkAccess(hostname, config) {
  const matchDomain = function(list) {
    for (let i = 0; i < list.length; i++) {
      const d = list[i];
      if (hostname === d || hostname.endsWith('.' + d)) return true;
    }
    return false;
  };
  if (matchDomain(config.BLOCKED_UPSTREAMS)) return { ok: false, reason: 'Domain blocked' };
  if (config.ENABLE_WHITELIST) {
    let allowed = false;
    for (let i = 0; i < config.ALLOWED_UPSTREAMS.length; i++) {
      const p = config.ALLOWED_UPSTREAMS[i];
      if (p.startsWith('.')) {
        if (hostname.endsWith(p) || hostname === p.slice(1)) { allowed = true; break; }
      } else {
        if (hostname === p || hostname.endsWith('.' + p)) { allowed = true; break; }
      }
    }
    if (!allowed) return { ok: false, reason: 'Domain not in whitelist' };
  }
  return { ok: true };
}

function isDirectDomain(hostname, config) {
  for (let i = 0; i < config.DIRECT_REDIRECT_DOMAINS.length; i++) {
    const d = config.DIRECT_REDIRECT_DOMAINS[i];
    if (hostname === d || hostname.endsWith('.' + d)) return true;
  }
  return false;
}

function isAutoProxyDomain(hostname, config) {
  for (let i = 0; i < config._autoProxyRegexes.length; i++) {
    if (config._autoProxyRegexes[i].test(hostname)) return true;
  }
  return false;
}

function isRewritableContent(contentType, config) {
  if (!contentType) return false;
  const ct = contentType.toLowerCase().split(';')[0].trim();
  for (const allowed of config._rewritableTypeSet) {
    if (ct === allowed || ct.startsWith(allowed)) return true;
  }
  return false;
}

function checkBot(request, config) {
  const ua = request.headers.get('User-Agent') || '';
  if (config.BLOCK_EMPTY_UA && !ua.trim()) {
    return new Response('Forbidden', { status: 403, headers: { 'Content-Type': 'text/plain' } });
  }
  const uaLower = ua.toLowerCase();
  for (let i = 0; i < config.BLOCKED_USER_AGENTS.length; i++) {
    if (uaLower.includes(config.BLOCKED_USER_AGENTS[i].toLowerCase())) {
      return new Response('Forbidden', { status: 403, headers: { 'Content-Type': 'text/plain' } });
    }
  }
  return null;
}

async function resolveProtocol(hostname, port, userProto, env, config) {
  if (userProto) return userProto;
  if (port === 443) return 'https';
  if (port === 80) return 'http';

  const key = hostname + ':' + (port || 'default');
  const ttl = config.PROTOCOL_CACHE_TTL * 1000;

  const mem = protocolCache.get(key);
  if (mem && Date.now() - mem.ts < ttl) return mem.proto;

  if (env && env.PROXY_KV) {
    try {
      const kv = await env.PROXY_KV.get('proto:' + key, { type: 'json' });
      if (kv && kv.proto) {
        protocolCache.set(key, { proto: kv.proto, ts: Date.now() });
        return kv.proto;
      }
    } catch (e) {
      console.error('[KV Read Error]', e.message);
    }
  }

  const proto = await probe(hostname, port, config);
  cacheProto(key, proto, env, config);
  return proto;
}

async function probe(hostname, port, config) {
  const host = port ? (hostname + ':' + port) : hostname;
  const controller = new AbortController();
  const timeoutId = setTimeout(function() { controller.abort(); }, config.PROBE_TIMEOUT);

  try {
    const res = await fetch('https://' + host + '/', {
      method: 'HEAD',
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return res.status < 500 ? 'https' : 'http';
  } catch (e) {
    clearTimeout(timeoutId);
    return 'http';
  }
}

function cacheProto(key, proto, env, config) {
  protocolCache.set(key, { proto: proto, ts: Date.now() });
  if (env && env.PROXY_KV) {
    env.PROXY_KV.put('proto:' + key, JSON.stringify({ proto: proto }), {
      expirationTtl: config.PROTOCOL_CACHE_TTL,
    }).catch(function(e) { console.error('[KV Write Error]', e.message); });
  }
}

function updateProtoCache(hostname, port, proto, env, config) {
  cacheProto(hostname + ':' + (port || 'default'), proto, env, config);
}

async function handleHTTP(ctx, target, protocol) {
  const request = ctx.request;
  const env = ctx.env;
  const config = ctx.config;
  const url = protocol + '://' + target.host + target.fullPath;
  const isMedia = checkMedia(target.path, request.headers, config);
  const isStream = checkStream(target.path, config);
  const headers = buildHeaders(request, target, protocol, isMedia, config);

  const opts = { method: request.method, headers: headers, redirect: 'manual' };
  if (['POST', 'PUT', 'PATCH'].includes(request.method) && request.body) {
    opts.body = request.body;
  }

  let res = null;
  let actualProto = protocol;

  try {
    res = await fetch(url, opts);
    if ([525, 526, 527, 530].includes(res.status) && protocol === 'https' && !target.userProtocol) {
      actualProto = 'http';
      updateProtoCache(target.hostname, target.port, 'http', env, config);
      headers.set('X-Forwarded-Proto', 'http');
      res = await fetch('http://' + target.host + target.fullPath, opts);
    }
  } catch (e) {
    if (protocol === 'https' && !target.userProtocol) {
      actualProto = 'http';
      updateProtoCache(target.hostname, target.port, 'http', env, config);
      try {
        headers.set('X-Forwarded-Proto', 'http');
        res = await fetch('http://' + target.host + target.fullPath, opts);
      } catch (e2) {
        return json({ error: 'Connection failed', detail: e2.message }, 502);
      }
    } else {
      return json({ error: 'Connection failed', detail: e.message }, 502);
    }
  }

  if ([301, 302, 303, 307, 308].includes(res.status)) {
    return handleRedirect(res, ctx, target, actualProto);
  }

  return buildResponse(res, ctx, target, actualProto, isMedia, isStream);
}

function buildHeaders(request, target, protocol, isMedia, config) {
  const h = new Headers();
  for (const pair of request.headers) {
    const k = pair[0];
    const v = pair[1];
    if (!config.HEADERS_TO_SKIP.includes(k.toLowerCase())) h.set(k, v);
  }
  h.set('Host', target.hostname);
  h.set('X-Forwarded-Proto', protocol);

  if (!isMedia) {
    const ip = request.headers.get('cf-connecting-ip');
    if (ip) {
      h.set('X-Real-IP', ip);
      const existing = request.headers.get('X-Forwarded-For');
      h.set('X-Forwarded-For', existing ? (existing + ', ' + ip) : ip);
    }
  }
  return h;
}

function handleRedirect(res, ctx, target, protocol) {
  const config = ctx.config;
  const loc = res.headers.get('Location');
  if (!loc) return res;

  try {
    const redir = new URL(loc, protocol + '://' + target.host);

    if (config.AUTO_REWRITE_ENABLED && isAutoProxyDomain(redir.hostname, config)) {
      const proxyUrl = buildProxyUrl(ctx.url.origin, redir);
      const h = new Headers(res.headers);
      h.set('Location', proxyUrl);
      return new Response(null, { status: res.status, headers: h });
    }

    if (isDirectDomain(redir.hostname, config) || !checkAccess(redir.hostname, config).ok) {
      const h = new Headers(res.headers);
      h.set('Location', redir.toString());
      return new Response(null, { status: res.status, headers: h });
    }

    const proxyUrl = buildProxyUrl(ctx.url.origin, redir);
    const h = new Headers(res.headers);
    h.set('Location', proxyUrl);
    return new Response(null, { status: res.status, headers: h });
  } catch (e) {
    console.error('[Redirect Parse Error]', e.message);
    return res;
  }
}

function buildProxyUrl(workerOrigin, targetUrl) {
  const proto = targetUrl.protocol.replace(':', '');
  const host = targetUrl.port ? (targetUrl.hostname + ':' + targetUrl.port) : targetUrl.hostname;
  return workerOrigin + '/' + proto + '://' + host + targetUrl.pathname + targetUrl.search;
}

async function buildResponse(res, ctx, target, protocol, isMedia, isStream) {
  const config = ctx.config;
  const request = ctx.request;
  const contentType = res.headers.get('Content-Type') || '';
  const contentLength = res.headers.get('Content-Length');
  const maxRewriteSize = 10 * 1024 * 1024;

  const shouldRewrite = config.AUTO_REWRITE_ENABLED &&
    isRewritableContent(contentType, config) &&
    !isStream &&
    (!contentLength || parseInt(contentLength, 10) < maxRewriteSize);

  let body = null;
  let rewriteApplied = false;
  let rewriteError = null;

  if (shouldRewrite && res.body) {
    const teed = res.body.tee();
    const stream1 = teed[0];
    const stream2 = teed[1];
    try {
      const reader = stream1.getReader();
      const chunks = [];
      let totalSize = 0;

      while (true) {
        const result = await reader.read();
        if (result.done) break;
        chunks.push(result.value);
        totalSize += result.value.length;
        if (totalSize > maxRewriteSize) {
          reader.cancel();
          throw new Error('Response too large for rewrite');
        }
      }

      const decoder = new TextDecoder();
      const text = decoder.decode(concatUint8Arrays(chunks));
      const rewritten = rewriteResponseUrls(text, ctx, target);
      body = rewritten.content;
      rewriteApplied = true;

      if (rewritten.foundDomains.length > 0) {
        console.log('[AutoProxy] Rewritten domains:', rewritten.foundDomains.join(', '));
      }
    } catch (e) {
      console.error('[Rewrite Error]', e.message);
      rewriteError = e.message;
      body = stream2;
    }
  } else {
    body = res.body;
  }

  const h = new Headers();
  for (const pair of res.headers) {
    const k = pair[0];
    const v = pair[1];
    const lk = k.toLowerCase();
    if (isStream || isMedia) {
      if (lk !== 'content-security-policy') h.set(k, v);
    } else {
      if (!config.HEADERS_TO_REMOVE.includes(lk)) h.set(k, v);
    }
  }

  if ((isStream || isMedia) && !h.has('Accept-Ranges')) {
    h.set('Accept-Ranges', 'bytes');
  }

  const origin = request.headers.get('Origin');
  h.set('Access-Control-Allow-Origin', origin || '*');
  h.set('Access-Control-Allow-Credentials', 'true');
  h.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS');
  h.set('Access-Control-Allow-Headers', request.headers.get('Access-Control-Request-Headers') || '*');
  h.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, X-Proxy-Protocol, X-Proxy-Target, X-Proxy-Rewrite');
  h.set('X-Proxy-Protocol', protocol);
  h.set('X-Proxy-Target', target.hostname);

  if (rewriteApplied) {
    h.set('X-Proxy-Rewrite', 'true');
    h.delete('Content-Length');
    h.delete('Content-Encoding');
    if (typeof body === 'string') {
      const encoded = new TextEncoder().encode(body);
      h.set('Content-Length', String(encoded.length));
    }
  } else if (rewriteError) {
    h.set('X-Proxy-Rewrite-Error', rewriteError);
  }

  return new Response(body, { status: res.status, headers: h });
}

function concatUint8Arrays(arrays) {
  let totalLength = 0;
  for (let i = 0; i < arrays.length; i++) {
    totalLength += arrays[i].length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (let i = 0; i < arrays.length; i++) {
    result.set(arrays[i], offset);
    offset += arrays[i].length;
  }
  return result;
}

function rewriteResponseUrls(content, ctx, target) {
  const config = ctx.config;
  const workerUrl = ctx.url;
  const workerOrigin = workerUrl.origin;
  const workerHost = workerUrl.hostname;
  const primaryHost = target.hostname;

  let result = content;
  const foundDomains = new Set();

  function processUrl(matchUrl, originalMatch) {
    try {
      const matchHost = matchUrl.hostname;
      const matchPort = matchUrl.port;
      const matchPath = matchUrl.pathname + matchUrl.search;
      const matchProto = matchUrl.protocol.replace(':', '');

      if (matchHost === primaryHost || matchHost === workerHost) return originalMatch;
      if (isDirectDomain(matchHost, config)) return originalMatch;
      if (!checkAccess(matchHost, config).ok) return originalMatch;

      if (isAutoProxyDomain(matchHost, config)) {
        foundDomains.add(matchHost);
        const hostWithPort = matchPort ? (matchHost + ':' + matchPort) : matchHost;
        return workerOrigin + '/' + matchProto + '://' + hostWithPort + matchPath;
      }

      const primaryParts = primaryHost.split('.');
      const matchParts = matchHost.split('.');
      if (primaryParts.length >= 2 && matchParts.length >= 2) {
        const primaryRoot = primaryParts.slice(-2).join('.');
        const matchRoot = matchParts.slice(-2).join('.');
        if (primaryRoot === matchRoot && matchHost !== primaryHost) {
          foundDomains.add(matchHost);
          const hostWithPort = matchPort ? (matchHost + ':' + matchPort) : matchHost;
          return workerOrigin + '/' + matchProto + '://' + hostWithPort + matchPath;
        }
      }
    } catch (e) {
      console.error('[URL Process Error]', e.message);
    }
    return originalMatch;
  }

  const escapedUrlPattern = /https?:\\\/\\\/([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(:\d+)?(\\\/[^"'\s]*)?/gi;
  result = result.replace(escapedUrlPattern, function(match) {
    try {
      const unescaped = match.replace(/\\\//g, '/');
      const matchUrl = new URL(unescaped);
      const processed = processUrl(matchUrl, unescaped);
      if (processed !== unescaped) {
        return processed.replace(/\//g, '\\/');
      }
    } catch (e) {}
    return match;
  });

  const urlPattern = /https?:\/\/([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(:\d+)?(\/[^"'\s<>\\]*)?/gi;
  result = result.replace(urlPattern, function(match) {
    try {
      const matchUrl = new URL(match);
      return processUrl(matchUrl, match);
    } catch (e) {}
    return match;
  });

  const protoRelativePattern = /(["'\s])\/\/([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(:\d+)?(\/[^"'\s<>\\]*)?/gi;
  result = result.replace(protoRelativePattern, function(match, prefix, domain, g2, g3, g4, port, path) {
    try {
      const fullUrl = 'https://' + domain + (port || '') + (path || '');
      const matchUrl = new URL(fullUrl);
      const matchHost = matchUrl.hostname;

      if (matchHost === primaryHost || matchHost === workerHost) return match;
      if (isDirectDomain(matchHost, config)) return match;
      if (!checkAccess(matchHost, config).ok) return match;

      if (isAutoProxyDomain(matchHost, config)) {
        foundDomains.add(matchHost);
        const hostWithPort = port ? (matchHost + port) : matchHost;
        return prefix + '//' + workerUrl.host + '/' + hostWithPort + (path || '');
      }
    } catch (e) {}
    return match;
  });

  return { content: result, foundDomains: Array.from(foundDomains) };
}

async function handleWS(ctx, target, protocol) {
  const h = new Headers();
  for (const pair of ctx.request.headers) {
    const k = pair[0];
    const v = pair[1];
    const lk = k.toLowerCase();
    if (lk !== 'host' && !ctx.config.HEADERS_TO_SKIP.includes(lk)) {
      h.set(k, v);
    }
  }
  h.set('Host', target.hostname);

  const wsUrl = protocol + '://' + target.host + target.fullPath;
  return fetch(wsUrl, { headers: h });
}

function checkMedia(path, headers, config) {
  for (let i = 0; i < config.MEDIA_PATH_PATTERNS.length; i++) {
    if (path.includes(config.MEDIA_PATH_PATTERNS[i])) return true;
  }
  if (headers && headers.get('X-Emby-Authorization')) return true;
  if (headers && headers.get('X-MediaBrowser-Token')) return true;
  return false;
}

function checkStream(path, config) {
  const lowerPath = path.toLowerCase();
  for (let i = 0; i < config.STREAM_PATTERNS.length; i++) {
    if (lowerPath.includes(config.STREAM_PATTERNS[i].toLowerCase())) return true;
  }
  return false;
}

async function recordStats(ctx, target) {
  if (!ctx.env || !ctx.env.ANALYTICS) return;

  let eventType = null;
  if (target.path.includes('/Playing')) eventType = 'playing';
  else if (target.path.includes('/PlaybackInfo')) eventType = 'playback_info';
  else if (target.path.includes('/stream')) eventType = 'stream';

  if (!eventType) return;

  ctx.env.ANALYTICS.writeDataPoint({
    blobs: [eventType, target.hostname, ctx.clientCountry, ctx.edgeColo],
    doubles: [1],
    indexes: [eventType],
  });
}

function cors(request) {
  const origin = request.headers.get('Origin');
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  });
}

function json(data, status) {
  if (status === undefined) status = 200;
  return new Response(JSON.stringify(data, null, 2), {
    status: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function finalize(res, startTime, ctx) {
  const h = new Headers(res.headers);
  h.set('X-Proxy-Time', (Date.now() - startTime) + 'ms');
  h.set('X-Proxy-Edge', ctx.edgeColo);
  h.set('X-Proxy-Version', '5.0.2');
  return new Response(res.body, { status: res.status, headers: h });
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function statusPage(ctx) {
  const clientIP = ctx.clientIP;
  const clientCountry = ctx.clientCountry;
  const edgeColo = ctx.edgeColo;
  const config = ctx.config;

  const flags = {
    CN: '🇨🇳', HK: '🇭🇰', TW: '🇹🇼', JP: '🇯🇵', KR: '🇰🇷',
    US: '🇺🇸', SG: '🇸🇬', DE: '🇩🇪', GB: '🇬🇧', FR: '🇫🇷',
    AU: '🇦🇺', CA: '🇨🇦', NL: '🇳🇱', RU: '🇷🇺', IN: '🇮🇳',
  };
  const flag = flags[clientCountry] || '🌐';
  const mode = config.ENABLE_WHITELIST ? '白名单模式' : '开放模式';
  const autoRewrite = config.AUTO_REWRITE_ENABLED ? '已启用' : '已禁用';
  const botProtection = config.ENABLE_BOT_PROTECTION ? '已启用' : '已禁用';
  const blockEmptyUA = config.BLOCK_EMPTY_UA ? '已启用' : '已禁用';

  let autoProxyList = '';
  const maxShow = Math.min(5, config.AUTO_PROXY_PATTERNS.length);
  for (let i = 0; i < maxShow; i++) {
    autoProxyList += '<code>' + escapeHtml(config.AUTO_PROXY_PATTERNS[i]) + '</code> ';
  }
  const moreCount = config.AUTO_PROXY_PATTERNS.length > 5
    ? '<span class="more">+' + (config.AUTO_PROXY_PATTERNS.length - 5) + ' more</span>'
    : '';

  const html = '<!DOCTYPE html>\n' +
'<html lang="zh-CN">\n' +
'<head>\n' +
'  <meta charset="UTF-8">\n' +
'  <meta name="viewport" content="width=device-width, initial-scale=1">\n' +
'  <title>Emby Proxy Gateway</title>\n' +
'  <style>\n' +
'    * { margin: 0; padding: 0; box-sizing: border-box; }\n' +
'    body {\n' +
'      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;\n' +
'      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);\n' +
'      min-height: 100vh;\n' +
'      display: flex;\n' +
'      align-items: center;\n' +
'      justify-content: center;\n' +
'      color: #e2e8f0;\n' +
'      padding: 20px;\n' +
'    }\n' +
'    .container { max-width: 560px; width: 100%; }\n' +
'    .card {\n' +
'      background: rgba(255, 255, 255, 0.05);\n' +
'      backdrop-filter: blur(10px);\n' +
'      border-radius: 16px;\n' +
'      padding: 30px;\n' +
'      border: 1px solid rgba(255, 255, 255, 0.1);\n' +
'      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);\n' +
'    }\n' +
'    h1 {\n' +
'      text-align: center;\n' +
'      font-size: 28px;\n' +
'      margin-bottom: 8px;\n' +
'      background: linear-gradient(90deg, #00d2ff, #3a7bd5);\n' +
'      -webkit-background-clip: text;\n' +
'      -webkit-text-fill-color: transparent;\n' +
'      background-clip: text;\n' +
'    }\n' +
'    .subtitle { text-align: center; color: #94a3b8; margin-bottom: 24px; font-size: 14px; }\n' +
'    .info-box {\n' +
'      background: linear-gradient(135deg, #667eea, #764ba2);\n' +
'      padding: 24px;\n' +
'      border-radius: 12px;\n' +
'      text-align: center;\n' +
'      margin-bottom: 24px;\n' +
'      box-shadow: 0 4px 16px rgba(102, 126, 234, 0.3);\n' +
'    }\n' +
'    .ip { font-size: 26px; font-weight: bold; font-family: Monaco, Consolas, monospace; }\n' +
'    .status-badge {\n' +
'      display: inline-block;\n' +
'      background: rgba(16, 185, 129, 0.9);\n' +
'      color: white;\n' +
'      padding: 6px 16px;\n' +
'      border-radius: 20px;\n' +
'      font-size: 12px;\n' +
'      font-weight: 600;\n' +
'      margin-top: 12px;\n' +
'    }\n' +
'    .info-grid {\n' +
'      display: grid;\n' +
'      gap: 1px;\n' +
'      background: rgba(255, 255, 255, 0.1);\n' +
'      border-radius: 8px;\n' +
'      overflow: hidden;\n' +
'      margin-bottom: 24px;\n' +
'    }\n' +
'    .row {\n' +
'      display: flex;\n' +
'      justify-content: space-between;\n' +
'      padding: 14px 16px;\n' +
'      background: rgba(30, 41, 59, 0.8);\n' +
'    }\n' +
'    .label { color: #94a3b8; font-size: 14px; }\n' +
'    .value { font-weight: 600; font-size: 14px; }\n' +
'    .value.enabled { color: #10b981; }\n' +
'    .value.disabled { color: #ef4444; }\n' +
'    .section { margin-bottom: 24px; }\n' +
'    .section h3 { font-size: 14px; color: #94a3b8; margin-bottom: 12px; }\n' +
'    .usage { background: rgba(0, 0, 0, 0.2); border-radius: 12px; padding: 20px; }\n' +
'    code {\n' +
'      display: inline-block;\n' +
'      background: rgba(0, 0, 0, 0.3);\n' +
'      padding: 4px 10px;\n' +
'      border-radius: 6px;\n' +
'      font-family: monospace;\n' +
'      font-size: 12px;\n' +
'      margin: 2px;\n' +
'      border-left: 2px solid #667eea;\n' +
'      color: #a5b4fc;\n' +
'    }\n' +
'    .code-block { display: block; padding: 12px 16px; margin-bottom: 10px; }\n' +
'    .patterns {\n' +
'      background: rgba(0, 0, 0, 0.2);\n' +
'      border-radius: 12px;\n' +
'      padding: 16px;\n' +
'      margin-bottom: 24px;\n' +
'    }\n' +
'    .patterns code { margin: 4px; }\n' +
'    .more { color: #64748b; font-size: 12px; margin-left: 8px; }\n' +
'    .note {\n' +
'      font-size: 12px;\n' +
'      color: #64748b;\n' +
'      text-align: center;\n' +
'      padding: 12px;\n' +
'      background: rgba(0, 0, 0, 0.2);\n' +
'      border-radius: 8px;\n' +
'    }\n' +
'    .note strong { color: #fbbf24; }\n' +
'    .feature-badge {\n' +
'      display: inline-block;\n' +
'      background: linear-gradient(135deg, #f093fb, #f5576c);\n' +
'      padding: 4px 10px;\n' +
'      border-radius: 12px;\n' +
'      font-size: 10px;\n' +
'      font-weight: 600;\n' +
'      margin-left: 8px;\n' +
'      vertical-align: middle;\n' +
'    }\n' +
'  </style>\n' +
'</head>\n' +
'<body>\n' +
'  <div class="container">\n' +
'    <div class="card">\n' +
'      <h1>🎬 Emby Proxy</h1>\n' +
'      <p class="subtitle">智能媒体反向代理网关 v5.0.2 <span class="feature-badge">AUTO REWRITE</span></p>\n' +
'      <div class="info-box">\n' +
'        <div class="ip">' + escapeHtml(clientIP) + '</div>\n' +
'        <div class="status-badge">● 服务正常</div>\n' +
'      </div>\n' +
'      <div class="info-grid">\n' +
'        <div class="row"><span class="label">访问地区</span><span class="value">' + flag + ' ' + escapeHtml(clientCountry) + '</span></div>\n' +
'        <div class="row"><span class="label">边缘节点</span><span class="value">' + escapeHtml(edgeColo) + '</span></div>\n' +
'        <div class="row"><span class="label">运行模式</span><span class="value">' + mode + '</span></div>\n' +
'        <div class="row"><span class="label">自动URL重写</span><span class="value ' + (config.AUTO_REWRITE_ENABLED ? 'enabled' : 'disabled') + '">' + autoRewrite + '</span></div>\n' +
'        <div class="row"><span class="label">防爬虫保护</span><span class="value ' + (config.ENABLE_BOT_PROTECTION ? 'enabled' : 'disabled') + '">' + botProtection + '</span></div>\n' +
'        <div class="row"><span class="label">拦截空UA</span><span class="value ' + (config.BLOCK_EMPTY_UA ? 'enabled' : 'disabled') + '">' + blockEmptyUA + '</span></div>\n' +
'      </div>\n' +
'      <div class="section patterns">\n' +
'        <h3>🎯 自动代理的后端域名模式</h3>\n' +
'        ' + autoProxyList + moreCount + '\n' +
'      </div>\n' +
'      <div class="section usage">\n' +
'        <h3>📖 使用方法</h3>\n' +
'        <code class="code-block">/{域名}/路径</code>\n' +
'        <code class="code-block">/{域名}:{端口}/路径</code>\n' +
'        <code class="code-block">/https://{域名}/路径</code>\n' +
'        <p style="font-size: 12px; color: #64748b; margin-top: 12px;">\n' +
'          示例：<code>/example.com/</code> → 自动代理前端及检测到的后端播放地址\n' +
'        </p>\n' +
'      </div>\n' +
'      <p class="note">\n' +
'        🔄 <strong>自动重写模式</strong>：响应中的外部播放地址将被自动转换为代理路径\n' +
'      </p>\n' +
'    </div>\n' +
'  </div>\n' +
'</body>\n' +
'</html>';

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    },
  });
}
