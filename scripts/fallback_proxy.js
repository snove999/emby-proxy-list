// @ts-nocheck
/* global PROXY_KV */

var CONFIG = {
  KV_KEY_PROXIES: 'best_proxies',
  GITHUB_MIRRORS: [
    'https://proxy.api.030101.xyz/https://raw.githubusercontent.com/snove999/emby-proxy-list/main/proxies.txt'
  ],
  // 上传密码
  UPLOAD_SECRET: 'xxx',
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
  ],
  
  REGION_PRIORITY: {
    'CN': ['HK', 'SG', 'JP', 'KR', 'TW'],
    'US': ['US', 'BR', 'NL', 'DE', 'GB'],
    'EU': ['NL', 'DE', 'GB', 'FR', 'IT', 'SE'],
    'ASIA': ['SG', 'HK', 'JP', 'KR', 'IN', 'AU'],
    'DEFAULT': ['SG', 'HK', 'JP', 'US', 'NL']
  }
};

var FALLBACK_PROXIES = [
  { ip: '47.74.157.194', region: 'SG' }, { ip: '8.212.12.98', region: 'HK' },
  { ip: '152.70.240.162', region: 'KR' }, { ip: '8.219.97.248', region: 'SG' },
  { ip: '144.24.95.220', region: 'KR' }, { ip: '152.67.203.34', region: 'KR' },
  { ip: '8.219.184.202', region: 'SG' }, { ip: '150.230.204.132', region: 'JP' },
  { ip: '141.144.195.224', region: 'NL' }, { ip: '141.147.160.166', region: 'JP' },
  { ip: '47.254.86.133', region: 'US' }, { ip: '143.47.183.52', region: 'NL' },
  { ip: '47.242.218.87', region: 'HK' }, { ip: '150.230.121.114', region: 'GB' },
  { ip: '168.138.165.174', region: 'SG' }
];

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

addEventListener('scheduled', function(event) {
  event.waitUntil(refreshFromGitHub());
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
    if (path === '/ip' || path === '/ip/') return handleIPPage(clientIP, clientCountry);
    if (path === '/ip/upload') return handleUploadPage();
    if (path === '/ip/api/proxies') return jsonResponse(await getProxyStatus());
    if (path === '/ip/api/refresh') return handleRefreshAPI();
    if (path === '/ip/api/upload') return handleUploadAPI(request);
    if (path === '/ip/api/status') return handleStatusAPI();
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

// 核心：解析应该使用的协议
async function resolveProtocol(hostname, port, userProtocol) {
  // 1. 用户明确指定，直接用
  if (userProtocol) return userProtocol;
  
  // 2. 标准端口，直接确定
  if (port === 443) return 'https';
  if (port === 80) return 'http';
  
  // 3. 检查内存缓存
  var cached = getCached(hostname, port);
  if (cached) return cached;
  
  // 4. 检查KV缓存
  var kvData = await kvGet('proto_' + hostname + ':' + (port || 'default'));
  if (kvData && kvData.p) {
    protocolCache[hostname + ':' + (port || 'default')] = { p: kvData.p, ts: Date.now() };
    return kvData.p;
  }
  
  // 5. 非标准端口：探测HTTPS
  var host = port ? hostname + ':' + port : hostname;
  var httpsOk = await probeHttps(host);
  var protocol = httpsOk ? 'https' : 'http';
  
  // 6. 缓存结果
  setCache(hostname, port, protocol);
  return protocol;
}

// 探测HTTPS是否可用（不返回内容，只判断是否成功）
async function probeHttps(host) {
  try {
    var res = await fetch('https://' + host + '/', {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0' },
      redirect: 'manual',
      cf: { cacheTtl: 0 }
    });
    // 状态码正常（包括重定向）且不是SSL错误
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
  
  // 确定协议
  var protocol = await resolveProtocol(parsed.hostname, parsed.port, parsed.userProtocol);
  var targetUrl = protocol + '://' + parsed.host + parsed.path + parsed.search;
  
  // 构建请求
  var isMedia = isMediaRequest(parsed.path, request.headers);
  var headers = buildHeaders(request, parsed.host, protocol, isMedia);
  var opts = { method: request.method, headers: headers, redirect: 'manual' };
  if (['POST', 'PUT', 'PATCH'].indexOf(request.method) !== -1) opts.body = request.body;
  
  // 发起请求
  var response;
  try {
    response = await fetch(targetUrl, opts);
  } catch (e) {
    // 如果HTTPS失败且不是用户指定的，尝试HTTP
    if (protocol === 'https' && !parsed.userProtocol) {
      setCache(parsed.hostname, parsed.port, 'http');
      response = await fetch('http://' + parsed.host + parsed.path + parsed.search, opts);
      protocol = 'http';
    } else {
      return jsonResponse({ error: 'Connection failed', detail: e.message }, 502);
    }
  }
  
  // 检查SSL错误（525/526/527），自动降级
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
  
  // 处理重定向
  if ([301, 302, 303, 307, 308].indexOf(response.status) !== -1) {
    var loc = response.headers.get('Location');
    if (loc) respHeaders.set('Location', rewriteUrl(loc, parsed.host, protocol, origin));
  }
  
  // 流媒体直接返回
  if (isStream || isMedia) {
    return new Response(response.body, { status: response.status, headers: respHeaders });
  }
  
  // HTML重写
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

async function getProxyStatus() {
  var data = await kvGet(CONFIG.KV_KEY_PROXIES);
  if (data && data.proxies && data.proxies.length) return data;
  return { proxies: FALLBACK_PROXIES, lastUpdate: 'N/A', source: 'fallback', count: FALLBACK_PROXIES.length };
}

async function refreshFromGitHub() {
  for (var i = 0; i < CONFIG.GITHUB_MIRRORS.length; i++) {
    try {
      var res = await fetch(CONFIG.GITHUB_MIRRORS[i] + '?t=' + Date.now(), {
        headers: { 'User-Agent': 'Mozilla/5.0', 'Cache-Control': 'no-cache' }
      });
      if (!res.ok) continue;
      var proxies = parseProxyList(await res.text());
      if (!proxies.length) continue;
      await kvPut(CONFIG.KV_KEY_PROXIES, { proxies: proxies, lastUpdate: new Date().toISOString(), source: 'github_' + (i+1), count: proxies.length }, { expirationTtl: 86400 });
      return { success: true, source: 'github_' + (i+1), count: proxies.length };
    } catch (e) {}
  }
  return { success: false, source: 'fallback', count: FALLBACK_PROXIES.length };
}

function parseProxyList(text) {
  var lines = text.split('\n'), proxies = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) continue;
    var m = line.match(/^([\d.]+)#(\w+)$/);
    if (m) { proxies.push({ ip: m[1], region: m[2] }); continue; }
    var ip = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (ip) proxies.push({ ip: ip[1], region: guessRegion(ip[1]) });
  }
  return proxies;
}

function guessRegion(ip) {
  var parts = ip.split('.');
  var p2 = parts[0] + '.' + parts[1];
  var p3 = parts[0] + '.' + parts[1] + '.' + parts[2];
  
  // 优先匹配前三段
  var map3 = {
    // Cloudflare 细分
    '104.19.32': 'CF-US', '104.19.33': 'CF-US',
    '198.41.208': 'CF-US', '198.41.209': 'CF-US',
    '198.41.214': 'CF-EU', '198.41.215': 'CF-EU',
    '198.41.192': 'CF-AS', '198.41.193': 'CF-AS',
    // Oracle
    '130.162.61': 'JP', '130.162.62': 'JP'
  };
  if (map3[p3]) return map3[p3];
  
  // 匹配前两段
  var map2 = {
    // Cloudflare (按区域细分)
    '104.16': 'CF-US', '104.17': 'CF-US', '104.18': 'CF-US', '104.19': 'CF-US',
    '104.20': 'CF-US', '104.21': 'CF-US', '104.22': 'CF-US', '104.23': 'CF-US',
    '104.24': 'CF-US', '104.25': 'CF-US', '104.26': 'CF-US', '104.27': 'CF-US',
    '172.64': 'CF-US', '172.65': 'CF-US', '172.66': 'CF-US', '172.67': 'CF-US',
    '162.158': 'CF-US', '162.159': 'CF-US',
    '198.41': 'CF-US',
    '173.245': 'CF-US',
    '108.162': 'CF-US',
    '141.101': 'CF-EU',
    '188.114': 'CF-EU',
    '190.93': 'CF-SA',
    '197.234': 'CF-AF',
    '103.21': 'CF-AS', '103.22': 'CF-AS', '103.31': 'CF-AS',
    '131.0': 'CF-EU',
    
    // 阿里云
    '8.208': 'DE', '8.209': 'SG', '8.210': 'HK', '8.211': 'SG',
    '8.212': 'HK', '8.213': 'ID', '8.214': 'JP', '8.215': 'ID',
    '8.216': 'MY', '8.217': 'HK', '8.218': 'HK', '8.219': 'SG',
    '8.220': 'AE', '8.221': 'JP', '8.222': 'SG', '8.223': 'MY',
    '47.74': 'SG', '47.76': 'SG',
    '47.242': 'HK', '47.243': 'HK', '47.245': 'MY',
    '47.254': 'US', '47.251': 'US', '47.252': 'US', '47.253': 'US',
    '47.88': 'US', '47.89': 'US', '47.90': 'DE', '47.91': 'DE',
    
    // Oracle
    '129.150': 'US', '129.151': 'UK', '129.152': 'US', '129.153': 'US', '129.154': 'US',
    '130.61': 'DE', '130.162': 'JP',
    '132.145': 'US', '132.226': 'BR',
    '138.2': 'JP', '138.3': 'KR',
    '140.238': 'JP',
    '141.144': 'NL', '141.145': 'NL', '141.147': 'JP', '141.148': 'JP',
    '143.47': 'NL',
    '144.21': 'US', '144.22': 'US', '144.24': 'KR',
    '146.56': 'KR', '146.235': 'IN',
    '150.136': 'US', '150.230': 'JP',
    '152.67': 'KR', '152.69': 'KR', '152.70': 'KR',
    '155.248': 'AU',
    '158.101': 'US', '158.178': 'AE', '158.179': 'IL',
    '168.138': 'SG',
    '192.9': 'US', '193.122': 'DE', '193.123': 'KR',
    
    // AWS
    '3.0': 'SG', '3.1': 'SG', '3.6': 'IN', '3.7': 'IN', '3.8': 'UK', '3.9': 'UK',
    '3.24': 'AU', '3.25': 'AU', '3.26': 'AU', '3.27': 'AU',
    '3.34': 'KR', '3.35': 'KR', '3.36': 'KR', '3.37': 'EU',
    '3.104': 'AU', '3.105': 'AU', '3.106': 'AU', '3.107': 'AU',
    '3.112': 'JP', '3.113': 'JP', '3.114': 'JP', '3.115': 'JP',
    '13.112': 'JP', '13.113': 'JP', '13.114': 'JP', '13.115': 'JP',
    '13.124': 'KR', '13.125': 'KR',
    '13.208': 'JP', '13.209': 'KR', '13.210': 'AU', '13.211': 'AU',
    '13.212': 'SG', '13.213': 'SG', '13.214': 'SG', '13.215': 'SG',
    '13.228': 'SG', '13.229': 'SG', '13.230': 'JP', '13.231': 'JP',
    '13.232': 'IN', '13.233': 'IN', '13.234': 'IN', '13.235': 'IN',
    '13.236': 'AU', '13.237': 'AU', '13.238': 'AU', '13.239': 'AU',
    '13.244': 'ZA', '13.245': 'ZA', '13.246': 'ZA',
    '13.250': 'SG', '13.251': 'SG',
    '15.152': 'JP', '15.164': 'KR', '15.165': 'KR',
    '15.184': 'BH', '15.185': 'BH',
    '16.162': 'HK', '16.163': 'HK',
    '18.136': 'SG', '18.138': 'SG', '18.139': 'SG', '18.140': 'SG', '18.141': 'SG',
    '18.162': 'HK', '18.163': 'HK', '18.164': 'HK', '18.165': 'HK',
    '18.166': 'HK', '18.167': 'HK',
    '18.176': 'JP', '18.177': 'JP', '18.178': 'JP', '18.179': 'JP',
    '18.180': 'JP', '18.181': 'JP', '18.182': 'JP', '18.183': 'JP',
    '35.72': 'JP', '35.73': 'JP', '35.74': 'JP', '35.75': 'JP',
    '35.76': 'JP', '35.77': 'JP', '35.78': 'JP', '35.79': 'JP',
    '52.68': 'JP', '52.69': 'JP', '52.78': 'KR', '52.79': 'KR',
    '52.196': 'JP', '52.197': 'JP', '52.198': 'JP', '52.199': 'JP',
    '52.220': 'SG', '52.221': 'SG',
    '54.64': 'JP', '54.65': 'JP', '54.66': 'AU', '54.67': 'US',
    '54.92': 'JP', '54.95': 'JP',
    '54.150': 'JP', '54.151': 'SG', '54.168': 'JP', '54.169': 'SG',
    '54.178': 'JP', '54.179': 'SG', '54.199': 'JP',
    '54.238': 'JP', '54.248': 'JP', '54.249': 'JP', '54.250': 'JP',
    '54.251': 'SG', '54.252': 'AU', '54.253': 'AU', '54.254': 'SG', '54.255': 'SG',
    
    // GCP
    '34.64': 'KR', '34.65': 'CH', '34.66': 'US', '34.67': 'US',
    '34.80': 'TW', '34.81': 'TW', '34.82': 'US', '34.83': 'US',
    '34.84': 'JP', '34.85': 'JP', '34.92': 'HK', '34.93': 'IN', '34.94': 'US',
    '34.96': 'HK', '34.97': 'JP', '34.98': 'NL', '34.100': 'IN',
    '34.124': 'SG', '34.126': 'SG', '34.127': 'US',
    '34.142': 'UK', '34.143': 'SG', '34.146': 'JP', '34.150': 'US',
    '35.185': 'US', '35.186': 'US', '35.187': 'TW', '35.188': 'US', '35.189': 'HK',
    '35.194': 'TW', '35.197': 'SG', '35.198': 'BR', '35.199': 'BR',
    '35.200': 'IN', '35.201': 'TW', '35.202': 'US', '35.203': 'US',
    '35.206': 'US', '35.207': 'DE', '35.208': 'US', '35.209': 'US',
    '35.213': 'JP', '35.214': 'NL', '35.215': 'AU', '35.216': 'KR',
    '35.217': 'NL', '35.219': 'JP', '35.220': 'HK', '35.221': 'HK',
    '35.222': 'US', '35.223': 'US', '35.224': 'US', '35.226': 'US',
    '35.229': 'TW', '35.230': 'US', '35.231': 'US', '35.232': 'US',
    '35.234': 'HK', '35.235': 'US', '35.236': 'TW', '35.237': 'US',
    '35.240': 'SG', '35.241': 'HK', '35.242': 'DE', '35.243': 'US',
    '35.244': 'IN', '35.245': 'US', '35.246': 'UK', '35.247': 'BR',
    
    // 腾讯云
    '43.128': 'TH', '43.129': 'HK', '43.130': 'US', '43.131': 'DE',
    '43.132': 'SG', '43.133': 'JP', '43.134': 'HK', '43.135': 'DE',
    '43.136': 'CN', '43.137': 'CN', '43.138': 'CN', '43.139': 'CN',
    '43.140': 'CN', '43.141': 'KR', '43.142': 'CN', '43.143': 'CN',
    '43.152': 'US', '43.153': 'US', '43.154': 'HK', '43.155': 'KR',
    '43.156': 'SG', '43.157': 'DE', '43.158': 'JP', '43.159': 'US',
    '43.160': 'CN', '43.163': 'IN',
    '49.51': 'HK',
    '101.32': 'SG', '101.33': 'HK', '101.34': 'CN', '101.35': 'CN',
    '119.28': 'HK', '119.29': 'CN',
    '129.204': 'CN', '129.211': 'CN',
    '150.109': 'HK', '150.138': 'CN',
    '162.14': 'US', '162.62': 'HK',
    '175.24': 'CN', '175.27': 'CN',
    '212.64': 'DE', '212.129': 'FR'
  };
  
  return map2[p2] || 'XX';
}

async function handleRefreshAPI() {
  var r = await refreshFromGitHub();
  return jsonResponse(r);
}

async function handleUploadAPI(request) {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405);
  try {
    var body = await request.json();
    if (body.secret !== CONFIG.UPLOAD_SECRET) return jsonResponse({ error: 'Invalid secret' }, 403);
    var proxies = parseProxyList(body.data || '');
    if (!proxies.length) return jsonResponse({ error: 'No valid proxies' }, 400);
    await kvPut(CONFIG.KV_KEY_PROXIES, { proxies: proxies, lastUpdate: new Date().toISOString(), source: 'upload', count: proxies.length }, { expirationTtl: 604800 });
    return jsonResponse({ success: true, count: proxies.length });
  } catch (e) { return jsonResponse({ error: e.message }, 400); }
}

async function handleStatusAPI() {
  var kv = typeof PROXY_KV !== 'undefined';
  var data = kv ? await kvGet(CONFIG.KV_KEY_PROXIES) : null;
  return jsonResponse({ kv: kv, data: data ? { source: data.source, count: data.count, lastUpdate: data.lastUpdate } : null });
}

function selectProxies(proxies, country, limit) {
  var p = CONFIG.REGION_PRIORITY.DEFAULT;
  if (['CN', 'HK', 'TW', 'MO'].indexOf(country) !== -1) p = CONFIG.REGION_PRIORITY.CN;
  else if (['US', 'CA', 'MX', 'BR'].indexOf(country) !== -1) p = CONFIG.REGION_PRIORITY.US;
  else if (['GB', 'DE', 'FR', 'IT', 'NL'].indexOf(country) !== -1) p = CONFIG.REGION_PRIORITY.EU;
  else if (['JP', 'KR', 'SG', 'IN', 'AU'].indexOf(country) !== -1) p = CONFIG.REGION_PRIORITY.ASIA;
  return proxies.slice().sort(function(a, b) {
    var ai = p.indexOf(a.region), bi = p.indexOf(b.region);
    return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
  }).slice(0, limit || 5);
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

function handleHomePage(clientIP, clientCountry) {
  var flag = { 
    'SG': '🇸🇬', 'HK': '🇭🇰', 'JP': '🇯🇵', 'KR': '🇰🇷', 
    'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'GB': '🇬🇧', 'UK': '🇬🇧',
    'CN': '🇨🇳', 'TW': '🇹🇼', 'AU': '🇦🇺', 'IN': '🇮🇳',
    'FR': '🇫🇷', 'ZA': '🇿🇦', 'BR': '🇧🇷', 'ID': '🇮🇩',
    'MY': '🇲🇾', 'TH': '🇹🇭', 'AE': '🇦🇪', 'IL': '🇮🇱',
    'CH': '🇨🇭', 'BH': '🇧🇭', 'EU': '🇪🇺',
    // Cloudflare 区域
    'CF-US': '☁️🇺🇸', 'CF-EU': '☁️🇪🇺', 'CF-AS': '☁️🌏', 
    'CF-SA': '☁️🌎', 'CF-AF': '☁️🌍',
    'XX': '🌐' 
  };
  var html = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Gateway</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#0f172a,#1e293b);min-height:100vh;color:#e2e8f0;padding:1.5rem}h1{text-align:center;font-size:2rem;margin-bottom:.5rem;background:linear-gradient(90deg,#38bdf8,#818cf8,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.sub{text-align:center;color:#94a3b8;margin-bottom:2rem}.container{max-width:800px;margin:0 auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.25rem;margin-bottom:1.5rem}.card{background:rgba(30,41,59,.7);backdrop-filter:blur(8px);border-radius:12px;padding:1.25rem;border:1px solid rgba(99,102,241,.15)}.card h2{font-size:1rem;margin-bottom:.75rem;color:#a5b4fc}.ip-box{background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:1.25rem;border-radius:10px;text-align:center;margin-bottom:.75rem}.ip-box .val{font-size:1.5rem;font-weight:700;font-family:monospace}.row{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,.05)}.row:last-child{border:none}.btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;padding:.6rem 1.25rem;border-radius:8px;cursor:pointer;font-weight:600}.btn:hover{transform:translateY(-1px)}.try{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);padding:1rem;border-radius:8px;margin-top:1rem}.try input{width:100%;padding:.65rem;border-radius:6px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-family:monospace;margin-bottom:.5rem}.example{background:#1e293b;padding:.75rem;border-radius:6px;margin:.5rem 0;font-family:monospace;font-size:.85rem;border-left:3px solid #6366f1}.note{background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.2);padding:.75rem;border-radius:8px;margin-top:.75rem;font-size:.85rem}.ip-link{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.25);padding:1rem;border-radius:8px;text-align:center;margin-top:1rem}.ip-link a{color:#34d399;font-weight:600;text-decoration:none}</style></head><body><div class="container"><h1>🌐 Proxy Gateway</h1><p class="sub">Emby智能反代</p><div class="grid"><div class="card"><h2>👤 访问信息</h2><div class="ip-box"><div class="val">' + clientIP + '</div></div><div class="row"><span>地区</span><span>' + (flag[clientCountry] || '🌐') + ' ' + clientCountry + '</span></div><div class="row"><span>时间</span><span>' + new Date().toLocaleString('zh-CN', {timeZone:'Asia/Shanghai'}) + '</span></div></div><div class="card"><h2>🔗 快捷入口</h2><div class="ip-link"><a href="/ip/">📡 优选IP管理 →</a></div></div></div><div class="card"><h2>🚀 使用方法</h2><div class="example">/<strong>目标:端口</strong> — 自动探测协议<br>/<strong>http://目标:端口</strong> — 强制HTTP<br>/<strong>https://目标</strong> — 强制HTTPS</div><div class="note">📌 端口443=HTTPS, 80=HTTP, 其他端口自主探测</div><div class="try"><input type="text" id="u" placeholder="example.com:8096"><button class="btn" id="go">Go</button></div></div></div><script>document.getElementById("go").onclick=function(){var v=document.getElementById("u").value.trim();if(v)window.open("/"+v,"_blank")};document.getElementById("u").onkeypress=function(e){if(e.key==="Enter")document.getElementById("go").onclick()}</script></body></html>';
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function handleIPPage(clientIP, clientCountry) {
  var status = await getProxyStatus();
  var recommended = selectProxies(status.proxies, clientCountry, 5);
  var flag = { 
    'SG': '🇸🇬', 'HK': '🇭🇰', 'JP': '🇯🇵', 'KR': '🇰🇷', 
    'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'GB': '🇬🇧', 'UK': '🇬🇧',
    'CN': '🇨🇳', 'TW': '🇹🇼', 'AU': '🇦🇺', 'IN': '🇮🇳',
    'FR': '🇫🇷', 'ZA': '🇿🇦', 'BR': '🇧🇷', 'ID': '🇮🇩',
    'MY': '🇲🇾', 'TH': '🇹🇭', 'AE': '🇦🇪', 'IL': '🇮🇱',
    'CH': '🇨🇭', 'BH': '🇧🇭', 'EU': '🇪🇺',
    // Cloudflare 区域
    'CF-US': '☁️🇺🇸', 'CF-EU': '☁️🇪🇺', 'CF-AS': '☁️🌏', 
    'CF-SA': '☁️🌎', 'CF-AF': '☁️🌍',
    'XX': '🌐' 
  };
  var recRows = '', allRows = '';
  for (var i = 0; i < recommended.length; i++) recRows += '<tr><td>' + (i+1) + '</td><td><code>' + recommended[i].ip + '</code></td><td>' + (flag[recommended[i].region]||'🌐') + ' ' + recommended[i].region + '</td></tr>';
  var display = status.proxies.slice(0, 50);
  for (var j = 0; j < display.length; j++) allRows += '<tr><td>' + (j+1) + '</td><td><code>' + display[j].ip + '</code></td><td>' + (flag[display[j].region]||'🌐') + ' ' + display[j].region + '</td></tr>';
  var html = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>优选IP</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#0f172a,#1e293b);min-height:100vh;color:#e2e8f0;padding:1.5rem}h1{text-align:center;font-size:1.75rem;margin-bottom:.5rem;background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.sub{text-align:center;color:#94a3b8;margin-bottom:1.5rem}.container{max-width:1000px;margin:0 auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.25rem;margin-bottom:1.5rem}.card{background:rgba(30,41,59,.7);border-radius:12px;padding:1.25rem;border:1px solid rgba(99,102,241,.15)}.card h2{font-size:1rem;margin-bottom:.75rem;color:#a5b4fc}.row{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,.05)}.row:last-child{border:none}table{width:100%;border-collapse:collapse}th,td{padding:.6rem;text-align:left;border-bottom:1px solid #334155}th{color:#94a3b8;font-size:.75rem}code{background:rgba(99,102,241,.15);padding:.15rem .4rem;border-radius:4px}.btn{background:#6366f1;color:#fff;border:none;padding:.6rem 1.25rem;border-radius:8px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block}.btn:hover{background:#4f46e5}a{color:#818cf8}</style></head><body><div class="container"><h1>📡 优选IP</h1><p class="sub">来源: ' + status.source + ' · ' + status.count + '个节点</p><div class="grid"><div class="card"><h2>📊 状态</h2><div class="row"><span>KV</span><span>' + (typeof PROXY_KV !== 'undefined' ? '✅' : '❌') + '</span></div><div class="row"><span>更新</span><span style="font-size:.75rem">' + (status.lastUpdate||'N/A') + '</span></div><div style="margin-top:.75rem"><a href="/ip/upload" class="btn">📤 管理</a></div></div><div class="card"><h2>⭐ 推荐 (' + (flag[clientCountry]||'🌐') + ' ' + clientCountry + ')</h2><table><thead><tr><th>#</th><th>IP</th><th>地区</th></tr></thead><tbody>' + recRows + '</tbody></table></div></div><div class="card"><h2>📋 全部</h2><table><thead><tr><th>#</th><th>IP</th><th>地区</th></tr></thead><tbody>' + allRows + '</tbody></table></div><div class="card" style="text-align:center"><a href="/">← 返回主页</a></div></div></body></html>';
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function handleUploadPage() {
  var html = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>节点管理</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#0f172a,#1e293b);min-height:100vh;color:#e2e8f0;padding:1.5rem}.container{max-width:700px;margin:0 auto}h1{text-align:center;font-size:1.5rem;margin-bottom:1.5rem;background:linear-gradient(90deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.card{background:rgba(30,41,59,.8);border-radius:12px;padding:1.25rem;border:1px solid #334155;margin-bottom:1.25rem}.card h2{font-size:1rem;margin-bottom:.75rem}label{display:block;margin-bottom:.4rem;color:#94a3b8}input,textarea{width:100%;padding:.65rem;border-radius:6px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-family:monospace}textarea{min-height:180px}.btn{background:#6366f1;color:#fff;border:none;padding:.65rem 1.2rem;border-radius:8px;cursor:pointer;font-weight:600;margin-top:.75rem}.btn:hover{background:#4f46e5}.result{margin-top:.75rem;padding:.75rem;border-radius:6px;display:none}.result.show{display:block}.result.ok{background:rgba(16,185,129,.1);border:1px solid #10b981}.result.err{background:rgba(239,68,68,.1);border:1px solid #ef4444}.tabs{display:flex;margin-bottom:.75rem}.tab{padding:.6rem 1rem;background:#1e293b;border:1px solid #334155;cursor:pointer}.tab:first-child{border-radius:6px 0 0 6px}.tab:last-child{border-radius:0 6px 6px 0}.tab.on{background:#6366f1;border-color:#6366f1}.pane{display:none}.pane.on{display:block}a{color:#818cf8}</style></head><body><div class="container"><h1>📤 节点管理</h1><div class="card"><div class="tabs"><div class="tab on" id="t0">🔄 刷新</div><div class="tab" id="t1">📋 上传</div></div><div id="p0" class="pane on"><p style="color:#94a3b8;margin-bottom:.75rem">从GitHub获取最新列表</p><button class="btn" id="refresh">🔄 刷新</button></div><div id="p1" class="pane"><label>🔑 密钥</label><input type="password" id="secret" placeholder="UPLOAD_SECRET"><label style="margin-top:.75rem">📋 列表 (IP#地区)</label><textarea id="data" placeholder="47.74.157.194#SG"></textarea><button class="btn" id="upload">🚀 上传</button></div><div id="result" class="result"></div></div><div class="card" style="text-align:center"><a href="/ip/">← 返回</a> · <a href="/">主页</a></div></div><script>var t0=document.getElementById("t0"),t1=document.getElementById("t1"),p0=document.getElementById("p0"),p1=document.getElementById("p1");t0.onclick=function(){t0.className="tab on";t1.className="tab";p0.className="pane on";p1.className="pane"};t1.onclick=function(){t1.className="tab on";t0.className="tab";p1.className="pane on";p0.className="pane"};document.getElementById("refresh").onclick=async function(){var r=document.getElementById("result");r.className="result show";r.textContent="⏳ 刷新中...";try{var res=await fetch("/ip/api/refresh");var d=await res.json();r.className="result show "+(d.success?"ok":"err");r.textContent=(d.success?"✅ 成功":"❌ 失败")+" · "+d.source+" · "+d.count+"个"}catch(e){r.className="result show err";r.textContent="❌ "+e.message}};document.getElementById("upload").onclick=async function(){var s=document.getElementById("secret").value.trim(),d=document.getElementById("data").value.trim(),r=document.getElementById("result");if(!s||!d){r.className="result show err";r.textContent="请填写完整";return}r.className="result show";r.textContent="⏳ 上传中...";try{var res=await fetch("/ip/api/upload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({secret:s,data:d})});var j=await res.json();r.className="result show "+(j.success?"ok":"err");r.textContent=j.success?"✅ 成功 ("+j.count+"个)":"❌ "+j.error}catch(e){r.className="result show err";r.textContent="❌ "+e.message}}</script></body></html>';
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
