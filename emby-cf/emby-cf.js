// @ts-nocheck
/* global PROXY_KV */

var CONFIG = {
  PROTOCOL_CACHE_TTL: 86400,
  REMOVE_HEADERS: ['content-security-policy', 'content-security-policy-report-only', 'x-frame-options'],
  ALLOWED_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
  BLOCKED_DOMAINS: [
    'google.com', 'google.com.hk', 'google.co.jp', 'googleapis.com', 'gstatic.com',
    'youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'ggpht.com',
    'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
    'whatsapp.com', 'messenger.com', 'twitter.com', 'x.com', 'twimg.com',
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com',
    'azure.com', 'bing.com', 'apple.com', 'icloud.com', 'mzstatic.com',
    'amazon.com', 'amazonaws.com', 'cloudfront.net',
    'netflix.com', 'nflxvideo.net', 'spotify.com', 'disneyplus.com',
    'cloudflare.com', 'cloudflareinsights.com', 'recaptcha.net',
    'paypal.com', 'stripe.com', 'alipay.com', 'tenpay.com'
  ],
  ALLOWED_DOMAINS: [],
  
  MEDIA_PATTERNS: [
    '/emby/', '/jellyfin/', '/mediabrowser/', '/videos/', '/Audio/', '/Items/',
    '/Users/', '/System/', '/Sessions/', '/Library/', '/Artists/', '/Albums/',
    '/Shows/', '/Movies/', '/socket', '/embywebsocket'
  ]
};

var protocolCache = {};

addEventListener('fetch', function(event) {
  var request = event.request;
  var upgrade = request.headers.get('Upgrade');
  
  if (upgrade && upgrade.toLowerCase() === 'websocket') {
    event.respondWith(handleWebSocket(request));
  } else {
    event.respondWith(handleRequest(request));
  }
});

async function handleWebSocket(request) {
  var url = new URL(request.url);
  var parsed = parseTargetUrl(url.pathname, url.search);
  if (!parsed) return new Response('WebSocket target not specified', { status: 400 });
  
  var protocol = await resolveProtocol(parsed.hostname, parsed.port, parsed.userProtocol);
  var targetUrl = protocol + '://' + parsed.host + parsed.path + parsed.search;
  
  var headers = new Headers();
  request.headers.forEach(function(v, k) {
    if (k.toLowerCase() !== 'host') headers.set(k, v);
  });
  headers.set('Host', parsed.host);
  
  return fetch(targetUrl, { method: request.method, headers: headers, body: request.body });
}

async function handleRequest(request) {
  var url = new URL(request.url);
  var clientIP = request.headers.get('CF-Connecting-IP') || 'Unknown';
  var clientCountry = request.headers.get('CF-IPCountry') || 'XX';
  var path = url.pathname;
  
  try {
    if (request.method === 'OPTIONS') return handleCORS(request);
    if (path === '/') return handleHomePage(clientIP, clientCountry);
    return handleProxy(request, url, clientCountry);
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

function handleCORS(request) {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
      'Access-Control-Allow-Methods': CONFIG.ALLOWED_METHODS.join(', '),
      'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400'
    }
  });
}

function parseTargetUrl(pathname, search) {
  var path = pathname.slice(1);
  if (!path) return null;
  
  var protocol = null;
  if (path.startsWith('https://')) { protocol = 'https'; path = path.slice(8); }
  else if (path.startsWith('http://')) { protocol = 'http'; path = path.slice(7); }
  
  var idx = path.indexOf('/');
  var host = idx === -1 ? path : path.substring(0, idx);
  var remainPath = idx === -1 ? '/' : path.substring(idx);
  
  var hostname = host.split(':')[0];
  if (!hostname || (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) && hostname.indexOf('.') === -1)) return null;
  
  var portMatch = host.match(/:(\d+)$/);
  
  return {
    userProtocol: protocol,
    host: host,
    hostname: hostname,
    port: portMatch ? parseInt(portMatch[1], 10) : null,
    path: remainPath,
    search: search
  };
}

// 协议缓存操作
function getCached(hostname, port) {
  var key = hostname + ':' + (port || 'default');
  var c = protocolCache[key];
  return (c && Date.now() - c.ts < CONFIG.PROTOCOL_CACHE_TTL * 1000) ? c.p : null;
}

function setCache(hostname, port, protocol) {
  var key = hostname + ':' + (port || 'default');
  protocolCache[key] = { p: protocol, ts: Date.now() };
  kvPut('proto_' + key, { p: protocol }, { expirationTtl: CONFIG.PROTOCOL_CACHE_TTL }).catch(function(){});
}

async function resolveProtocol(hostname, port, userProtocol) {
  if (userProtocol) return userProtocol;
  if (port === 443) return 'https';
  if (port === 80) return 'http';
  
  var cached = getCached(hostname, port);
  if (cached) return cached;
  
  var kvData = await kvGet('proto_' + hostname + ':' + (port || 'default'));
  if (kvData && kvData.p) {
    protocolCache[hostname + ':' + (port || 'default')] = { p: kvData.p, ts: Date.now() };
    return kvData.p;
  }
  
  var host = port ? hostname + ':' + port : hostname;
  var httpsOk = await probeHttps(host);
  var protocol = httpsOk ? 'https' : 'http';
  
  setCache(hostname, port, protocol);
  return protocol;
}

async function probeHttps(host) {
  try {
    var res = await fetch('https://' + host + '/', {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0' },
      redirect: 'manual',
      cf: { cacheTtl: 0 }
    });
    return res.status < 500 || res.status >= 600;
  } catch (e) {
    return false;
  }
}

async function handleProxy(request, url, clientCountry) {
  var parsed = parseTargetUrl(url.pathname, url.search);
  if (!parsed) return handleHomePage(request.headers.get('CF-Connecting-IP') || 'Unknown', clientCountry);
  
  if (isBlocked(parsed.hostname)) return blockedPage(parsed.host, parsed.hostname);
  
  if (CONFIG.ALLOWED_DOMAINS.length > 0) {
    var allowed = false;
    for (var i = 0; i < CONFIG.ALLOWED_DOMAINS.length; i++) {
      if (parsed.hostname === CONFIG.ALLOWED_DOMAINS[i] || parsed.hostname.endsWith('.' + CONFIG.ALLOWED_DOMAINS[i])) {
        allowed = true; break;
      }
    }
    if (!allowed) return jsonResponse({ error: 'Domain not allowed' }, 403);
  }
  
  var protocol = await resolveProtocol(parsed.hostname, parsed.port, parsed.userProtocol);
  var targetUrl = protocol + '://' + parsed.host + parsed.path + parsed.search;
  
  var isMedia = isMediaRequest(parsed.path, request.headers);
  var headers = buildHeaders(request, parsed.host, protocol, isMedia);
  var opts = { method: request.method, headers: headers, redirect: 'manual' };
  if (['POST', 'PUT', 'PATCH'].indexOf(request.method) !== -1) opts.body = request.body;
  
  var response;
  try {
    response = await fetch(targetUrl, opts);
  } catch (e) {
    if (protocol === 'https' && !parsed.userProtocol) {
      setCache(parsed.hostname, parsed.port, 'http');
      response = await fetch('http://' + parsed.host + parsed.path + parsed.search, opts);
      protocol = 'http';
    } else {
      return jsonResponse({ error: 'Connection failed', detail: e.message }, 502);
    }
  }
  
  if ([525, 526, 527].indexOf(response.status) !== -1 && protocol === 'https' && !parsed.userProtocol) {
    setCache(parsed.hostname, parsed.port, 'http');
    headers.set('X-Forwarded-Proto', 'http');
    response = await fetch('http://' + parsed.host + parsed.path + parsed.search, opts);
    protocol = 'http';
  }
  
  return processResponse(response, request, url.origin, parsed, protocol, isMedia);
}

function isMediaRequest(path, headers) {
  for (var i = 0; i < CONFIG.MEDIA_PATTERNS.length; i++) {
    if (path.indexOf(CONFIG.MEDIA_PATTERNS[i]) !== -1) return true;
  }
  return !!(headers && (headers.get('X-Emby-Authorization') || headers.get('X-MediaBrowser-Token')));
}

function isStreamRequest(path, ct) {
  var patterns = ['/Videos/', '/Audio/', '/stream', '.m3u8', '.ts', '.mp4', '.mkv', '.webm', '.mp3', '.flac'];
  for (var i = 0; i < patterns.length; i++) if (path.indexOf(patterns[i]) !== -1) return true;
  return ct && (ct.indexOf('video/') !== -1 || ct.indexOf('audio/') !== -1);
}

function isBlocked(hostname) {
  for (var i = 0; i < CONFIG.BLOCKED_DOMAINS.length; i++) {
    var d = CONFIG.BLOCKED_DOMAINS[i];
    if (hostname === d || hostname.endsWith('.' + d)) return true;
  }
  return false;
}

function buildHeaders(request, targetHost, protocol, isMedia) {
  var headers = new Headers();
  var skip = ['host', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'cf-ew-via', 'cdn-loop', 'cf-worker'];
  
  request.headers.forEach(function(v, k) {
    if (skip.indexOf(k.toLowerCase()) === -1) headers.set(k, v);
  });
  
  headers.set('Host', targetHost);
  headers.set('X-Forwarded-Proto', protocol);
  
  if (!isMedia) {
    headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || '');
    headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
  }
  
  if (!headers.has('User-Agent')) {
    headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
  }
  
  return headers;
}

function processResponse(response, request, origin, parsed, protocol, isMedia) {
  var respHeaders = new Headers();
  var isStream = isStreamRequest(parsed.path, response.headers.get('Content-Type'));
  
  response.headers.forEach(function(v, k) {
    var lk = k.toLowerCase();
    if (isStream || isMedia) {
      if (lk !== 'content-security-policy') respHeaders.set(k, v);
    } else {
      if (CONFIG.REMOVE_HEADERS.indexOf(lk) === -1) respHeaders.set(k, v);
    }
  });
  
  if ((isStream || isMedia) && !respHeaders.has('Accept-Ranges')) {
    respHeaders.set('Accept-Ranges', 'bytes');
  }
  
  respHeaders.set('Access-Control-Allow-Origin', request.headers.get('Origin') || '*');
  respHeaders.set('Access-Control-Allow-Credentials', 'true');
  respHeaders.set('Access-Control-Allow-Methods', CONFIG.ALLOWED_METHODS.join(', '));
  respHeaders.set('Access-Control-Allow-Headers', '*');
  respHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, ETag');
  respHeaders.set('X-Proxy-Protocol', protocol);
  
  if ([301, 302, 303, 307, 308].indexOf(response.status) !== -1) {
    var loc = response.headers.get('Location');
    if (loc) respHeaders.set('Location', rewriteUrl(loc, parsed.host, protocol, origin));
  }
  
  if (isStream || isMedia) {
    return new Response(response.body, { status: response.status, headers: respHeaders });
  }
  
  var ct = response.headers.get('Content-Type') || '';
  if (ct.indexOf('text/html') !== -1) {
    return response.text().then(function(html) {
      var base = origin + '/' + protocol + '://' + parsed.host;
      html = html.replace(/(href|src|action)=(["'])\//gi, '$1=$2' + base + '/');
      html = html.replace(new RegExp((protocol + '://' + parsed.host).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), base);
      return new Response(html, { status: response.status, headers: respHeaders });
    });
  }
  
  return new Response(response.body, { status: response.status, headers: respHeaders });
}

function rewriteUrl(loc, host, protocol, origin) {
  try {
    if (loc.startsWith('/')) return origin + '/' + protocol + '://' + host + loc;
    if (loc.startsWith('http://') || loc.startsWith('https://')) {
      var u = new URL(loc);
      if (isBlocked(u.hostname)) return loc;
      return origin + '/' + u.protocol.replace(':', '') + '://' + u.host + u.pathname + u.search;
    }
    return origin + '/' + protocol + '://' + host + '/' + loc;
  } catch (e) { return loc; }
}

function blockedPage(url, hostname) {
  var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Blocked</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e2e8f0;padding:2rem}.c{max-width:480px;text-align:center}.i{font-size:4rem;margin-bottom:1rem}h1{color:#f87171;margin-bottom:.75rem}p{color:#94a3b8;margin-bottom:1.5rem}.b{background:#6366f1;color:#fff;padding:.6rem 1.2rem;border-radius:8px;text-decoration:none;display:inline-block;margin:.25rem}.b:hover{background:#4f46e5}</style></head><body><div class="c"><div class="i">🛡️</div><h1>无法代理</h1><p>' + hostname + '</p><a href="https://' + url + '" class="b" target="_blank">直接访问</a><a href="/" class="b">返回</a></div></body></html>';
  return new Response(html, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function kvGet(key) {
  if (typeof PROXY_KV === 'undefined') return null;
  try { return await PROXY_KV.get(key, { type: 'json' }); } catch (e) { return null; }
}

async function kvPut(key, value, opts) {
  if (typeof PROXY_KV === 'undefined') return false;
  try { await PROXY_KV.put(key, JSON.stringify(value), opts || {}); return true; } catch (e) { return false; }
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

function handleHomePage(clientIP, clientCountry) {
  var flag = { 'CN': '🇨🇳', 'HK': '🇭🇰', 'TW': '🇹🇼', 'US': '🇺🇸', 'JP': '🇯🇵', 'SG': '🇸🇬', 'XX': '🌐' };
  var html = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Gateway</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#0f172a,#1e293b);min-height:100vh;color:#e2e8f0;padding:1.5rem}h1{text-align:center;font-size:2rem;margin-bottom:.5rem;background:linear-gradient(90deg,#38bdf8,#818cf8,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.sub{text-align:center;color:#94a3b8;margin-bottom:2rem}.container{max-width:800px;margin:0 auto}.card{background:rgba(30,41,59,.7);backdrop-filter:blur(8px);border-radius:12px;padding:1.25rem;border:1px solid rgba(99,102,241,.15);margin-bottom:1.5rem}.card h2{font-size:1rem;margin-bottom:.75rem;color:#a5b4fc}.ip-box{background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:1.25rem;border-radius:10px;text-align:center;margin-bottom:.75rem}.ip-box .val{font-size:1.5rem;font-weight:700;font-family:monospace}.row{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,.05)}.btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;padding:.6rem 1.25rem;border-radius:8px;cursor:pointer;font-weight:600}.example{background:#1e293b;padding:.75rem;border-radius:6px;margin:.5rem 0;font-family:monospace;font-size:.85rem;border-left:3px solid #6366f1}.try input{width:100%;padding:.65rem;border-radius:6px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-family:monospace;margin-bottom:.5rem}</style></head><body><div class="container"><h1>🌐 Proxy Gateway</h1><p class="sub">智能反代服务</p><div class="card"><h2>👤 访问信息</h2><div class="ip-box"><div class="val">' + clientIP + '</div></div><div class="row"><span>地区</span><span>' + (flag[clientCountry] || '🌐') + ' ' + clientCountry + '</span></div></div><div class="card"><h2>🚀 使用方法</h2><div class="example">/<strong>目标:端口</strong> — 自动探测协议<br>/<strong>http://目标:端口</strong> — 强制HTTP<br>/<strong>https://目标</strong> — 强制HTTPS</div><div class="try"><input type="text" id="u" placeholder="example.com:8096"><button class="btn" id="go">Go</button></div></div></div><script>document.getElementById("go").onclick=function(){var v=document.getElementById("u").value.trim();if(v)window.open("/"+v,"_blank")};document.getElementById("u").onkeypress=function(e){if(e.key==="Enter")document.getElementById("go").onclick()}</script></body></html>';
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
