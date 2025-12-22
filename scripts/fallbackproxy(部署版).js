/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *                    Cloudflare Worker - Emby 智能反向代理 v4.0
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * 绑定说明：
 * 
 * [vars]
 * ENABLE_WHITELIST = "false"
 * PROTOCOL_CACHE_TTL = "86400"
 * 
 * [[kv_namespaces]]
 * binding = "PROXY_KV"
 * id = "emby-proxy-kv"
 * 
 * [[analytics_engine_datasets]]
 * binding = "ANALYTICS"
 * dataset = "emby_proxy_stats"
 */

// ═══════════════════════════════════════════════════════════════════════════════
//                                 默认配置
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  BLOCKED_UPSTREAMS: [
    'google.com', 'googleapis.com', 'gstatic.com',
    'facebook.com', 'twitter.com', 'x.com',
    'paypal.com', 'stripe.com', 'alipay.com',
    'cloudflare.com', 'amazonaws.com', 'azure.com',
  ],
  DIRECT_REDIRECT_DOMAINS: [
    'quark.cn', 'uc.cn',
    '115.com', '115cdn.com', '115cdn.net',
    'aliyundrive.com', 'aliyundrive.net',
    '189.cn', 'ctyunxs.cn', 'mini189.cn', 'telecomjs.com',
    'xunlei.com', 'voicehub.top', 'xiaoya.pro',
  ],
  ALLOWED_UPSTREAMS: [],
  MEDIA_PATH_PATTERNS: [
    '/emby/', '/jellyfin/', '/mediabrowser/',
    '/Videos/', '/Audio/', '/Items/', '/Users/', '/Sessions/',
    '/System/', '/Library/', '/PlaybackInfo', '/Playing',
    '/socket', '/embywebsocket',
  ],
  STREAM_PATTERNS: [
    '/stream', '.m3u8', '.ts', '.mp4', '.mkv', '.webm',
    '.mp3', '.flac', '.aac', '.wav',
  ],
  HEADERS_TO_REMOVE: ['content-security-policy', 'content-security-policy-report-only', 'x-frame-options'],
  HEADERS_TO_SKIP: ['host', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cf-ew-via', 'cdn-loop', 'cf-worker'],
};

// 运行时配置缓存
let runtimeConfig = null;
let configLoadedAt = 0;
const CONFIG_CACHE_TTL = 300000; // 5分钟

const protocolCache = new Map();

// ═══════════════════════════════════════════════════════════════════════════════
//                                 主入口
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    
    try {
      // 加载配置
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

// ═══════════════════════════════════════════════════════════════════════════════
//                                 配置加载
// ═══════════════════════════════════════════════════════════════════════════════

async function loadConfig(env) {
  // 缓存有效则直接返回
  if (runtimeConfig && Date.now() - configLoadedAt < CONFIG_CACHE_TTL) {
    return runtimeConfig;
  }

  const config = { ...DEFAULT_CONFIG };

  // 1. 从环境变量加载简单配置
  config.ENABLE_WHITELIST = env.ENABLE_WHITELIST === 'true';
  config.PROTOCOL_CACHE_TTL = parseInt(env.PROTOCOL_CACHE_TTL || '86400', 10);

  // 2. 从 KV 加载列表配置（如果绑定了 KV）
  if (env.PROXY_KV) {
    try {
      const [blocked, direct, allowed] = await Promise.all([
        env.PROXY_KV.get('config:blocked_upstreams', { type: 'json' }),
        env.PROXY_KV.get('config:direct_redirect_domains', { type: 'json' }),
        env.PROXY_KV.get('config:allowed_upstreams', { type: 'json' }),
      ]);
      
      if (blocked?.length) config.BLOCKED_UPSTREAMS = blocked;
      if (direct?.length) config.DIRECT_REDIRECT_DOMAINS = direct;
      if (allowed?.length) config.ALLOWED_UPSTREAMS = allowed;
    } catch (e) {
      console.error('[Config] KV load failed:', e.message);
    }
  }

  runtimeConfig = config;
  configLoadedAt = Date.now();
  return config;
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 上下文 & 路由
// ═══════════════════════════════════════════════════════════════════════════════

function buildContext(request, env, config) {
  const url = new URL(request.url);
  const cf = request.cf || {};
  return {
    request, env, url, config,
    clientIP: request.headers.get('cf-connecting-ip') || 'unknown',
    clientCountry: cf.country || 'XX',
    edgeColo: cf.colo || 'unknown',
    isWebSocket: request.headers.get('upgrade')?.toLowerCase() === 'websocket',
  };
}

async function route(ctx, waitCtx) {
  const { url, request, isWebSocket, config } = ctx;
  const path = url.pathname;

  if (path === '/') return statusPage(ctx);
  if (path === '/health') return new Response('OK');
  if (request.method === 'OPTIONS') return cors(request);

  const target = parseUrl(url);
  if (!target) return json({ error: 'Invalid URL format' }, 400);

  const access = checkAccess(target.hostname, config);
  if (!access.ok) return json({ error: access.reason, domain: target.hostname }, 403);

  const protocol = await resolveProtocol(target.hostname, target.port, target.userProtocol, ctx.env, config);

  // 统计（非阻塞）
  waitCtx.waitUntil(recordStats(ctx, target));

  return isWebSocket 
    ? handleWS(ctx, target, protocol) 
    : handleHTTP(ctx, target, protocol);
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 URL 解析
// ═══════════════════════════════════════════════════════════════════════════════

function parseUrl(workerUrl) {
  let path = workerUrl.pathname.slice(1);
  if (!path) return null;

  let userProtocol = null;
  for (const prefix of ['https://', 'http://', 'https/', 'http/']) {
    if (path.startsWith(prefix)) {
      userProtocol = prefix.startsWith('https') ? 'https' : 'http';
      path = path.slice(prefix.length);
      break;
    }
  }

  const slashIdx = path.indexOf('/');
  const host = slashIdx === -1 ? path : path.substring(0, slashIdx);
  const remainPath = slashIdx === -1 ? '/' : path.substring(slashIdx);

  const colonIdx = host.lastIndexOf(':');
  let hostname, port = null;
  if (colonIdx > 0 && !host.includes(']')) {
    hostname = host.substring(0, colonIdx);
    port = parseInt(host.substring(colonIdx + 1), 10);
    if (isNaN(port)) port = null;
  } else {
    hostname = host;
  }

  if (!hostname || !isValidHost(hostname)) return null;

  return {
    userProtocol, host, hostname, port,
    path: remainPath,
    search: workerUrl.search,
    fullPath: remainPath + workerUrl.search,
  };
}

function isValidHost(h) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || 
         /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(h);
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 安全层
// ═══════════════════════════════════════════════════════════════════════════════

function checkAccess(hostname, config) {
  const matchDomain = (list) => list.some(d => hostname === d || hostname.endsWith('.' + d));
  
  if (matchDomain(config.BLOCKED_UPSTREAMS)) {
    return { ok: false, reason: 'Domain blocked' };
  }
  
  if (config.ENABLE_WHITELIST) {
    const allowed = config.ALLOWED_UPSTREAMS.some(p => {
      if (p.startsWith('.')) return hostname.endsWith(p) || hostname === p.slice(1);
      return hostname === p || hostname.endsWith('.' + p);
    });
    if (!allowed) return { ok: false, reason: 'Domain not in whitelist' };
  }
  
  return { ok: true };
}

function isDirectDomain(hostname, config) {
  return config.DIRECT_REDIRECT_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 协议探测
// ═══════════════════════════════════════════════════════════════════════════════

async function resolveProtocol(hostname, port, userProto, env, config) {
  if (userProto) return userProto;
  if (port === 443) return 'https';
  if (port === 80) return 'http';

  const key = `${hostname}:${port || 'default'}`;
  const ttl = config.PROTOCOL_CACHE_TTL * 1000;

  const mem = protocolCache.get(key);
  if (mem && Date.now() - mem.ts < ttl) {
    return mem.proto;
  }

  if (env?.PROXY_KV) {
    try {
      const kv = await env.PROXY_KV.get(`proto:${key}`, { type: 'json' });
      if (kv?.proto) {
        protocolCache.set(key, { proto: kv.proto, ts: Date.now() });
        return kv.proto;
      }
    } catch {}
  }

  const proto = await probe(hostname, port);
  cacheProto(key, proto, env, config);
  return proto;
}

async function probe(hostname, port) {
  const host = port ? `${hostname}:${port}` : hostname;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(`https://${host}/`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return res.status < 500 ? 'https' : 'http';
  } catch {
    clearTimeout(timeoutId);
    return 'http';
  }
}

function cacheProto(key, proto, env, config) {
  protocolCache.set(key, { proto, ts: Date.now() });
  env?.PROXY_KV?.put(`proto:${key}`, JSON.stringify({ proto }), { 
    expirationTtl: config.PROTOCOL_CACHE_TTL 
  }).catch(() => {});
}

function updateProtoCache(hostname, port, proto, env, config) {
  cacheProto(`${hostname}:${port || 'default'}`, proto, env, config);
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 HTTP 处理
// ═══════════════════════════════════════════════════════════════════════════════

async function handleHTTP(ctx, target, protocol) {
  const { request, env, config } = ctx;
  const url = `${protocol}://${target.host}${target.fullPath}`;
  const isMedia = checkMedia(target.path, request.headers, config);
  const isStream = checkStream(target.path, config);
  const headers = buildHeaders(request, target, protocol, isMedia, config);

  const opts = { method: request.method, headers, redirect: 'manual' };
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    opts.body = request.body;
  }

  let res, actualProto = protocol;

  try {
    res = await fetch(url, opts);
    
    if ([525, 526, 527, 530].includes(res.status) && protocol === 'https' && !target.userProtocol) {
      actualProto = 'http';
      updateProtoCache(target.hostname, target.port, 'http', env, config);
      headers.set('X-Forwarded-Proto', 'http');
      res = await fetch(`http://${target.host}${target.fullPath}`, opts);
    }
  } catch (e) {
    if (protocol === 'https' && !target.userProtocol) {
      actualProto = 'http';
      updateProtoCache(target.hostname, target.port, 'http', env, config);
      try {
        headers.set('X-Forwarded-Proto', 'http');
        res = await fetch(`http://${target.host}${target.fullPath}`, opts);
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
  for (const [k, v] of request.headers) {
    if (!config.HEADERS_TO_SKIP.includes(k.toLowerCase())) h.set(k, v);
  }
  h.set('Host', target.hostname);
  h.set('X-Forwarded-Proto', protocol);
  
  if (!isMedia) {
    const ip = request.headers.get('cf-connecting-ip');
    if (ip) {
      h.set('X-Real-IP', ip);
      h.set('X-Forwarded-For', ip);
    }
  }
  return h;
}

function handleRedirect(res, ctx, target, protocol) {
  const { config } = ctx;
  const loc = res.headers.get('Location');
  if (!loc) return res;

  try {
    const redir = new URL(loc, `${protocol}://${target.host}`);
    
    if (isDirectDomain(redir.hostname, config) || !checkAccess(redir.hostname, config).ok) {
      const h = new Headers(res.headers);
      h.set('Location', redir.toString());
      return new Response(null, { status: res.status, headers: h });
    }
    
    const proxyUrl = `${ctx.url.origin}/${redir.protocol.replace(':', '')}://${redir.host}${redir.pathname}${redir.search}`;
    const h = new Headers(res.headers);
    h.set('Location', proxyUrl);
    return new Response(null, { status: res.status, headers: h });
  } catch {
    return res;
  }
}

function buildResponse(res, ctx, target, protocol, isMedia, isStream) {
  const { config } = ctx;
  const h = new Headers();
  
  for (const [k, v] of res.headers) {
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
  
  h.set('Access-Control-Allow-Origin', ctx.request.headers.get('Origin') || '*');
  h.set('Access-Control-Allow-Credentials', 'true');
  h.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS');
  h.set('Access-Control-Allow-Headers', '*');
  h.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
  h.set('X-Proxy-Protocol', protocol);
  h.set('X-Proxy-Target', target.hostname);

  return new Response(res.body, { status: res.status, headers: h });
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 WebSocket
// ═══════════════════════════════════════════════════════════════════════════════

async function handleWS(ctx, target, protocol) {
  const h = new Headers();
  for (const [k, v] of ctx.request.headers) {
    if (k.toLowerCase() !== 'host') h.set(k, v);
  }
  h.set('Host', target.hostname);
  return fetch(`${protocol}://${target.host}${target.fullPath}`, { headers: h });
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 媒体识别
// ═══════════════════════════════════════════════════════════════════════════════

function checkMedia(path, headers, config) {
  return config.MEDIA_PATH_PATTERNS.some(p => path.includes(p)) ||
         !!(headers?.get('X-Emby-Authorization') || headers?.get('X-MediaBrowser-Token'));
}

function checkStream(path, config) {
  return config.STREAM_PATTERNS.some(p => path.includes(p));
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 统计 (Analytics Engine)
// ═══════════════════════════════════════════════════════════════════════════════

async function recordStats(ctx, target) {
  // 检查 Analytics Engine 绑定
  if (!ctx.env?.ANALYTICS) return;

  // 识别事件类型
  let eventType = null;
  if (target.path.includes('/Playing')) eventType = 'playing';
  else if (target.path.includes('/PlaybackInfo')) eventType = 'playback_info';
  
  if (!eventType) return;

  // 写入 Analytics Engine（完全异步，无延迟）
  try {
    ctx.env.ANALYTICS.writeDataPoint({
      blobs: [
        eventType,              // blob1: 事件类型
        target.hostname,        // blob2: 目标域名
        ctx.clientCountry,      // blob3: 用户地区
        ctx.edgeColo,           // blob4: 边缘节点
      ],
      doubles: [1],             // double1: 计数
      indexes: [eventType],     // 索引
    });
  } catch (e) {
    console.error('[Analytics]', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 工具函数
// ═══════════════════════════════════════════════════════════════════════════════

function cors(request) {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function finalize(res, startTime, ctx) {
  const h = new Headers(res.headers);
  h.set('X-Proxy-Time', `${Date.now() - startTime}ms`);
  h.set('X-Proxy-Edge', ctx.edgeColo);
  return new Response(res.body, { status: res.status, headers: h });
}

// ═══════════════════════════════════════════════════════════════════════════════
//                                 状态页
// ═══════════════════════════════════════════════════════════════════════════════

function statusPage(ctx) {
  const { clientIP, clientCountry, edgeColo, config } = ctx;
  
  const flags = {
    CN: '🇨🇳', HK: '🇭🇰', TW: '🇹🇼', JP: '🇯🇵', KR: '🇰🇷',
    US: '🇺🇸', SG: '🇸🇬', DE: '🇩🇪', GB: '🇬🇧', FR: '🇫🇷',
    AU: '🇦🇺', CA: '🇨🇦', NL: '🇳🇱', RU: '🇷🇺', IN: '🇮🇳',
  };
  const flag = flags[clientCountry] || '🌐';
  const mode = config.ENABLE_WHITELIST ? '白名单模式' : '开放模式';
  
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Emby Proxy Gateway</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #e2e8f0;
      padding: 20px;
    }
    .container { max-width: 500px; width: 100%; }
    .card {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border-radius: 16px;
      padding: 30px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    h1 {
      text-align: center;
      font-size: 28px;
      margin-bottom: 8px;
      background: linear-gradient(90deg, #00d2ff, #3a7bd5);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle { text-align: center; color: #94a3b8; margin-bottom: 24px; font-size: 14px; }
    .info-box {
      background: linear-gradient(135deg, #667eea, #764ba2);
      padding: 24px;
      border-radius: 12px;
      text-align: center;
      margin-bottom: 24px;
      box-shadow: 0 4px 16px rgba(102, 126, 234, 0.3);
    }
    .ip { font-size: 26px; font-weight: bold; font-family: 'Monaco', 'Consolas', monospace; }
    .status-badge {
      display: inline-block;
      background: rgba(16, 185, 129, 0.9);
      color: white;
      padding: 6px 16px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      margin-top: 12px;
    }
    .info-grid {
      display: grid;
      gap: 1px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 24px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      padding: 14px 16px;
      background: rgba(30, 41, 59, 0.8);
    }
    .label { color: #94a3b8; font-size: 14px; }
    .value { font-weight: 600; font-size: 14px; }
    .usage { background: rgba(0, 0, 0, 0.2); border-radius: 12px; padding: 20px; }
    .usage h3 { font-size: 14px; color: #94a3b8; margin-bottom: 16px; }
    code {
      display: block;
      background: rgba(0, 0, 0, 0.3);
      padding: 12px 16px;
      border-radius: 8px;
      font-family: monospace;
      font-size: 13px;
      margin-bottom: 10px;
      border-left: 3px solid #667eea;
      color: #a5b4fc;
    }
    .note {
      font-size: 12px;
      color: #64748b;
      margin-top: 20px;
      text-align: center;
      padding: 12px;
      background: rgba(0, 0, 0, 0.2);
      border-radius: 8px;
    }
    .note strong { color: #fbbf24; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🎬 Emby Proxy</h1>
      <p class="subtitle">智能媒体反向代理网关 v4.0</p>
      <div class="info-box">
        <div class="ip">${clientIP}</div>
        <div class="status-badge">● 服务正常</div>
      </div>
      <div class="info-grid">
        <div class="row"><span class="label">访问地区</span><span class="value">${flag} ${clientCountry}</span></div>
        <div class="row"><span class="label">边缘节点</span><span class="value">${edgeColo}</span></div>
        <div class="row"><span class="label">运行模式</span><span class="value">${mode}</span></div>
      </div>
      <div class="usage">
        <h3>📖 使用方法</h3>
        <code>/{域名}/路径</code>
        <code>/{域名}:{端口}/路径</code>
        <code>/https://{域名}/路径</code>
      </div>
      <p class="note">
        ${config.ENABLE_WHITELIST 
          ? '⚠️ 当前为 <strong>白名单模式</strong>' 
          : '🛡️ 当前为 <strong>开放模式</strong>，已启用黑名单保护'}
      </p>
    </div>
  </div>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
