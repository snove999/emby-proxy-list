// @ts-nocheck
/* global PROXY_KV */

// ==================== 配置区域 ====================
var CONFIG = {
  KV_KEY_PROXIES: 'best_proxies',
  KV_KEY_HEALTH: 'proxy_health',
  
//优选IP地址，可自行添加删除
  GITHUB_MIRRORS: [
    'https://proxy.api.030101.xyz/https://raw.githubusercontent.com/snove999/emby-proxy-list/refs/heads/main/proxies.txt',
    'https://ghproxy.com/https://raw.githubusercontent.com/snove999/emby-proxy-list/main/proxies.txt',
    'https://raw.fastgit.org/snove999/emby-proxy-list/main/proxies.txt',
    'https://cdn.jsdelivr.net/gh/snove999/emby-proxy-list@main/proxies.txt'
  ],
  
  CACHE_TTL: 3600,
  // 后台访问密码
  UPLOAD_SECRET: 'xxx',
  
  PROXY_CONFIG: {
    ENABLE_CACHE: true,
    CACHE_TTL: 3600,
    PRESERVE_HOST: false,
    CUSTOM_HEADERS: {},
    REMOVE_RESPONSE_HEADERS: [
      'content-security-policy',
      'content-security-policy-report-only',
      'x-frame-options',
      'x-content-type-options',
      'strict-transport-security'
    ],
    ENABLE_CORS: true,
    ALLOWED_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
    PATH_REWRITE: {},
    BLOCKED_PATHS: [],
    ALLOWED_DOMAINS: [],
    
    BLOCKED_DOMAINS: [
      'google.com', 'google.com.hk', 'google.co.jp', 'googleapis.com', 'gstatic.com',
      'youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'ggpht.com',
      'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
      'whatsapp.com', 'messenger.com',
      'twitter.com', 'x.com', 'twimg.com',
      'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com',
      'azure.com', 'bing.com',
      'apple.com', 'icloud.com', 'mzstatic.com',
      'amazon.com', 'amazonaws.com', 'cloudfront.net',
      'netflix.com', 'nflxvideo.net', 'spotify.com', 'disneyplus.com',
      'cloudflare.com', 'cloudflareinsights.com', 'recaptcha.net',
      'paypal.com', 'stripe.com', 'alipay.com', 'tenpay.com'
    ]
  },
  
  REGION_PRIORITY: {
    'CN': ['HK', 'SG', 'JP', 'KR', 'TW'],
    'US': ['US', 'BR', 'NL', 'DE', 'GB'],
    'EU': ['NL', 'DE', 'GB', 'FR', 'IT', 'SE'],
    'ASIA': ['SG', 'HK', 'JP', 'KR', 'IN', 'AU'],
    'DEFAULT': ['SG', 'HK', 'JP', 'US', 'NL']
  }
};

var FALLBACK_PROXIES = [
  { ip: '47.74.157.194', region: 'SG' },
  { ip: '8.212.12.98', region: 'HK' },
  { ip: '152.70.240.162', region: 'KR' },
  { ip: '8.219.97.248', region: 'SG' },
  { ip: '144.24.95.220', region: 'KR' },
  { ip: '152.67.203.34', region: 'KR' },
  { ip: '8.219.184.202', region: 'SG' },
  { ip: '150.230.204.132', region: 'JP' },
  { ip: '141.144.195.224', region: 'NL' },
  { ip: '141.147.160.166', region: 'JP' },
  { ip: '47.254.86.133', region: 'US' },
  { ip: '143.47.183.52', region: 'NL' },
  { ip: '47.242.218.87', region: 'HK' },
  { ip: '150.230.121.114', region: 'GB' },
  { ip: '168.138.165.174', region: 'SG' }
];

// ==================== 事件监听 ====================
addEventListener('fetch', function(event) {
  event.respondWith(handleRequest(event.request));
});

addEventListener('scheduled', function(event) {
  event.waitUntil(scheduledRefresh());
});

// ==================== 主处理函数 ====================
async function handleRequest(request) {
  var url = new URL(request.url);
  var clientIP = request.headers.get('CF-Connecting-IP') || 'Unknown';
  var clientCountry = request.headers.get('CF-IPCountry') || 'XX';
  var pathname = url.pathname;
  
  try {
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }
    
    switch (pathname) {
      case '/':
        return handleRootPage(clientIP, clientCountry);
      case '/upload':
        return handleUploadPage();
      case '/api/proxies':
        return handleProxyListAPI();
      case '/api/refresh':
        return handleRefreshAPI(url);
      case '/api/health':
        return handleHealthAPI();
      case '/api/kv-debug':
        return handleKVDebugAPI();
      case '/api/upload':
        return handleUploadAPI(request);
    }
    
    return handleDomainProxy(request, url, clientCountry);
    
  } catch (error) {
    return jsonResponse({ error: error.message, stack: error.stack }, 500);
  }
}

// ==================== CORS 处理 ====================
function handleCORS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': CONFIG.PROXY_CONFIG.ALLOWED_METHODS.join(', '),
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Max-Age': '86400'
    }
  });
}

// ==================== 解析目标URL ====================
function parseTargetUrl(pathname, search) {
  var pathWithoutSlash = pathname.slice(1);
  
  if (!pathWithoutSlash) {
    return null;
  }
  
  var protocol = 'https';
  var hostWithPort;
  var remainingPath;
  
  var userSpecifiedProtocol = pathWithoutSlash.startsWith('https://') || pathWithoutSlash.startsWith('http://');
  
  // 处理显式协议前缀
  if (pathWithoutSlash.startsWith('https://')) {
    protocol = 'https';
    pathWithoutSlash = pathWithoutSlash.slice(8);
  } else if (pathWithoutSlash.startsWith('http://')) {
    protocol = 'http';
    pathWithoutSlash = pathWithoutSlash.slice(7);
  }
  
  // 分离主机和路径
  var firstSlashIndex = pathWithoutSlash.indexOf('/');
  if (firstSlashIndex === -1) {
    hostWithPort = pathWithoutSlash;
    remainingPath = '/';
  } else {
    hostWithPort = pathWithoutSlash.substring(0, firstSlashIndex);
    remainingPath = pathWithoutSlash.substring(firstSlashIndex);
  }
  
  // 验证域名
  var hostname = hostWithPort.split(':')[0];
  if (!hostname || hostname.indexOf('.') === -1) {
    return null;
  }
  
  // 仅当用户未显式指定协议时，根据端口智能选择
  if (!userSpecifiedProtocol) {
    var portMatch = hostWithPort.match(/:(\d+)$/);
    if (portMatch) {
      var port = parseInt(portMatch[1], 10);
      if (port !== 443) {
        protocol = 'http';
      }
    }
  }
  
  var targetUrl = protocol + '://' + hostWithPort + remainingPath + search;
  
  return {
    url: targetUrl,
    protocol: protocol,
    host: hostWithPort,
    hostname: hostname,
    path: remainingPath
  };
}

// ==================== 域名模式反代 ====================
async function handleDomainProxy(request, url, clientCountry) {
  var parsed = parseTargetUrl(url.pathname, url.search);
  
  if (!parsed) {
    return handleRootPage(
      request.headers.get('CF-Connecting-IP') || 'Unknown',
      request.headers.get('CF-IPCountry') || 'XX'
    );
  }
  
  return executeProxy(request, parsed.url, clientCountry, url.origin, parsed);
}

// ==================== 域名黑名单检查 ====================
function isBlockedDomain(hostname) {
  var blocked = CONFIG.PROXY_CONFIG.BLOCKED_DOMAINS;
  var i, domain;
  
  for (i = 0; i < blocked.length; i++) {
    domain = blocked[i];
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      return true;
    }
  }
  
  return false;
}

function getBlockedReason(hostname) {
  var categories = {
    google: {
      keywords: ['google', 'youtube', 'gstatic', 'googleapis', 'googlevideo', 'ytimg', 'ggpht'],
      category: 'Google',
      icon: '🔍',
      reason: 'Google 系服务有严格的反代理检测，会触发人机验证'
    },
    meta: {
      keywords: ['facebook', 'fb', 'instagram', 'whatsapp', 'messenger', 'fbcdn', 'cdninstagram'],
      category: 'Meta',
      icon: '📘',
      reason: 'Meta 系服务会检测并阻止代理访问'
    },
    microsoft: {
      keywords: ['microsoft', 'live', 'outlook', 'office', 'microsoftonline', 'azure', 'bing'],
      category: 'Microsoft',
      icon: '🪟',
      reason: 'Microsoft 服务需要直接访问以确保安全'
    },
    apple: {
      keywords: ['apple', 'icloud', 'mzstatic'],
      category: 'Apple',
      icon: '🍎',
      reason: 'Apple 服务有严格的安全验证机制'
    },
    twitter: {
      keywords: ['twitter', 'x.com', 'twimg'],
      category: 'Twitter/X',
      icon: '🐦',
      reason: 'Twitter/X 会检测并阻止代理访问'
    },
    amazon: {
      keywords: ['amazon', 'amazonaws', 'cloudfront'],
      category: 'Amazon',
      icon: '📦',
      reason: 'Amazon 服务有反代理保护'
    },
    streaming: {
      keywords: ['netflix', 'nflxvideo', 'spotify', 'disneyplus'],
      category: '流媒体',
      icon: '🎬',
      reason: '流媒体服务有严格的地区和代理检测'
    }
  };
  
  var key, cat, i;
  for (key in categories) {
    cat = categories[key];
    for (i = 0; i < cat.keywords.length; i++) {
      if (hostname.indexOf(cat.keywords[i]) !== -1) {
        return { category: cat.category, icon: cat.icon, reason: cat.reason };
      }
    }
  }
  
  return { category: '受保护网站', icon: '🛡️', reason: '该网站有反代理保护机制' };
}

// ==================== 阻止页面生成 ====================
function generateBlockedPage(targetUrl, hostname) {
  var info = getBlockedReason(hostname);
  
  var html = '<!DOCTYPE html><html lang="zh-CN"><head>';
  html += '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
  html += '<title>无法代理此网站</title>';
  html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e4e4e7;padding:2rem}.container{max-width:600px;text-align:center}.icon{font-size:5rem;margin-bottom:1rem}h1{font-size:1.8rem;margin-bottom:1rem;color:#f87171}.card{background:rgba(30,41,59,0.8);border-radius:16px;padding:2rem;border:1px solid #334155;margin:1.5rem 0;text-align:left}.card h2{font-size:1rem;color:#9ca3af;margin-bottom:0.5rem}.card p{color:#e4e4e7;word-break:break-all}.reason{background:rgba(239,68,68,0.1);border-left:3px solid #ef4444;padding:1rem;margin:1rem 0;border-radius:0 8px 8px 0}.suggestion{background:rgba(16,185,129,0.1);border-left:3px solid #10b981;padding:1rem;margin:1rem 0;border-radius:0 8px 8px 0}.btn{background:#6366f1;color:white;border:none;padding:0.75rem 1.5rem;border-radius:8px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block;margin:0.5rem;transition:all 0.2s}.btn:hover{background:#4f46e5;transform:translateY(-1px)}.btn-outline{background:transparent;border:1px solid #6366f1}.btn-outline:hover{background:rgba(99,102,241,0.1)}code{background:rgba(99,102,241,0.2);padding:0.2rem 0.5rem;border-radius:4px;font-size:0.9rem}</style></head><body>';
  html += '<div class="container"><div class="icon">' + info.icon + '</div>';
  html += '<h1>无法代理此网站</h1>';
  html += '<p style="color:#9ca3af">检测到您尝试代理的是 <strong>' + info.category + '</strong> 服务</p>';
  html += '<div class="card"><h2>目标网址</h2><p><code>' + targetUrl + '</code></p></div>';
  html += '<div class="reason"><strong>❌ 为什么无法代理？</strong><br><br>' + info.reason + '。使用 Cloudflare Worker 代理这类网站会导致：<br>• 触发人机验证（CAPTCHA）<br>• 账号安全风险提示<br>• 页面功能异常</div>';
  html += '<div class="suggestion"><strong>✅ 建议</strong><br><br>请直接访问原始网站，或使用 VPN/科学上网工具。</div>';
  html += '<div style="margin-top:1.5rem"><a href="' + targetUrl + '" class="btn" target="_blank">🔗 直接访问原网站</a><a href="/" class="btn btn-outline">🏠 返回首页</a></div></div></body></html>';

  return new Response(html, {
    status: 403,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

// ==================== 执行反代请求 ====================
async function executeProxy(request, targetUrl, clientCountry, proxyOrigin, parsedTarget) {
  var target;
  
  try {
    target = new URL(targetUrl);
  } catch (e) {
    return jsonResponse({ error: 'Invalid URL: ' + targetUrl }, 400);
  }
  
  if (isBlockedDomain(target.hostname)) {
    return generateBlockedPage(targetUrl, target.hostname);
  }
  
  // 域名白名单检查
  if (CONFIG.PROXY_CONFIG.ALLOWED_DOMAINS.length > 0) {
    var isAllowed = false;
    for (var i = 0; i < CONFIG.PROXY_CONFIG.ALLOWED_DOMAINS.length; i++) {
      var allowedDomain = CONFIG.PROXY_CONFIG.ALLOWED_DOMAINS[i];
      if (target.hostname === allowedDomain || target.hostname.endsWith('.' + allowedDomain)) {
        isAllowed = true;
        break;
      }
    }
    if (!isAllowed) {
      return jsonResponse({ error: 'Domain not allowed: ' + target.hostname }, 403);
    }
  }
  
  // 路径黑名单检查
  for (var j = 0; j < CONFIG.PROXY_CONFIG.BLOCKED_PATHS.length; j++) {
    var pattern = new RegExp(CONFIG.PROXY_CONFIG.BLOCKED_PATHS[j]);
    if (pattern.test(target.pathname)) {
      return jsonResponse({ error: 'Path blocked' }, 403);
    }
  }
  
  // 构建请求头
  var headers = new Headers();
  var skipHeaders = [
    'host', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
    'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'cf-ew-via',
    'cdn-loop', 'cf-worker', 'cf-access-client-id', 'cf-access-client-device-type'
  ];
  
  request.headers.forEach(function(value, key) {
    if (skipHeaders.indexOf(key.toLowerCase()) === -1) {
      headers.set(key, value);
    }
  });
  
  headers.set('Host', target.host);
  headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || '');
  headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
  headers.set('X-Forwarded-Proto', target.protocol.replace(':', ''));
  
  if (!headers.has('User-Agent')) {
    headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  }
  
  var customHeaders = Object.keys(CONFIG.PROXY_CONFIG.CUSTOM_HEADERS);
  for (var m = 0; m < customHeaders.length; m++) {
    headers.set(customHeaders[m], CONFIG.PROXY_CONFIG.CUSTOM_HEADERS[customHeaders[m]]);
  }
  
  var fetchOptions = {
    method: request.method,
    headers: headers,
    redirect: 'manual'
  };
  
  if (['POST', 'PUT', 'PATCH'].indexOf(request.method) !== -1) {
    fetchOptions.body = request.body;
  }
  
  var response;
  try {
    response = await fetch(target.toString(), fetchOptions);
  } catch (e) {
    return jsonResponse({ error: 'Fetch failed', message: e.message, targetUrl: target.toString() }, 502);
  }
  
  // 构建响应头
  var responseHeaders = new Headers();
  response.headers.forEach(function(value, key) {
    if (CONFIG.PROXY_CONFIG.REMOVE_RESPONSE_HEADERS.indexOf(key.toLowerCase()) === -1) {
      responseHeaders.set(key, value);
    }
  });
  
  if (CONFIG.PROXY_CONFIG.ENABLE_CORS) {
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', CONFIG.PROXY_CONFIG.ALLOWED_METHODS.join(', '));
    responseHeaders.set('Access-Control-Allow-Headers', '*');
    responseHeaders.set('Access-Control-Expose-Headers', '*');
  }
  
  responseHeaders.set('X-Proxied-By', 'Smart-Proxy-Gateway');
  responseHeaders.set('X-Target-URL', target.toString());
  responseHeaders.set('X-Target-Protocol', target.protocol);
  
  var proxyBasePath = buildProxyBasePath(proxyOrigin, parsedTarget);
  
  if ([301, 302, 303, 307, 308].indexOf(response.status) !== -1) {
    var location = response.headers.get('Location');
    if (location) {
      var newLocation = rewriteRedirectUrl(location, target, proxyOrigin, parsedTarget);
      responseHeaders.set('Location', newLocation);
    }
  }
  
  var contentType = response.headers.get('Content-Type') || '';
  var body = response.body;
  
  if (contentType.indexOf('text/html') !== -1) {
    var htmlText = await response.text();
    htmlText = rewriteHtmlLinks(htmlText, target, proxyBasePath);
    body = htmlText;
  }
  
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

// ==================== 构建代理基础路径 ====================
function buildProxyBasePath(proxyOrigin, parsedTarget) {
  if (parsedTarget.protocol === 'http') {
    return proxyOrigin + '/http://' + parsedTarget.host;
  }
  return proxyOrigin + '/' + parsedTarget.host;
}

// ==================== 重写重定向 URL ====================
function rewriteRedirectUrl(location, originalTarget, proxyOrigin, parsedTarget) {
  try {
    var redirectUrl;
    
    if (location.startsWith('/')) {
      if (parsedTarget && parsedTarget.protocol === 'http') {
        return proxyOrigin + '/http://' + originalTarget.host + location;
      }
      return proxyOrigin + '/' + originalTarget.host + location;
    }
    
    if (location.startsWith('http://') || location.startsWith('https://')) {
      redirectUrl = new URL(location);
      
      if (isBlockedDomain(redirectUrl.hostname)) {
        return location;
      }
      
      if (redirectUrl.protocol === 'http:') {
        return proxyOrigin + '/http://' + redirectUrl.host + redirectUrl.pathname + redirectUrl.search;
      }
      return proxyOrigin + '/' + redirectUrl.host + redirectUrl.pathname + redirectUrl.search;
    }
    
    if (parsedTarget && parsedTarget.protocol === 'http') {
      return proxyOrigin + '/http://' + originalTarget.host + '/' + location;
    }
    return proxyOrigin + '/' + originalTarget.host + '/' + location;
    
  } catch (e) {
    return location;
  }
}

// ==================== 重写 HTML 中的链接 ====================
function rewriteHtmlLinks(html, target, proxyBase) {
  var targetHost = target.host;
  
  var protocolPrefix = target.protocol === 'http:' ? 'http://' : '';
  html = html.replace(/(href|src|action)=(["'])\//gi, '$1=$2/' + protocolPrefix + targetHost + '/');
  
  var escapedHttpsOrigin = ('https://' + target.host).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  var httpsRegex = new RegExp(escapedHttpsOrigin, 'gi');
  var httpsProxyBase = proxyBase.indexOf('/http://') !== -1 ? proxyBase.replace('/http://' + targetHost, '/' + targetHost) : proxyBase;
  html = html.replace(httpsRegex, httpsProxyBase);
  
  var escapedHttpOrigin = ('http://' + target.host).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  var httpRegex = new RegExp(escapedHttpOrigin, 'gi');
  var httpProxyBase = proxyBase.indexOf('/http://') !== -1 ? proxyBase : proxyBase.replace('/' + targetHost, '/http://' + targetHost);
  html = html.replace(httpRegex, httpProxyBase);
  
  return html;
}

// ==================== KV 操作封装 ====================
async function kvGet(key) {
  if (typeof PROXY_KV === 'undefined') {
    return null;
  }
  try {
    return await PROXY_KV.get(key, { type: 'json' });
  } catch (e) {
    return null;
  }
}

async function kvPut(key, value, options) {
  if (typeof PROXY_KV === 'undefined') {
    return false;
  }
  try {
    var data = typeof value === 'string' ? value : JSON.stringify(value);
    await PROXY_KV.put(key, data, options || {});
    return true;
  } catch (e) {
    return false;
  }
}

// ==================== 获取代理状态 ====================
async function getProxyStatus() {
  var cached = await kvGet(CONFIG.KV_KEY_PROXIES);
  if (cached && cached.proxies && cached.proxies.length > 0) {
    return cached;
  }
  return {
    proxies: FALLBACK_PROXIES,
    lastUpdate: 'N/A',
    source: 'fallback',
    count: FALLBACK_PROXIES.length
  };
}

// ==================== 定时刷新 ====================
async function scheduledRefresh() {
  console.log('开始定时刷新...');
  var result = await refreshFromGitHub();
  console.log('刷新完成:', result.source, result.count);
  return result;
}

// ==================== 从 GitHub Raw 刷新 ====================
async function refreshFromGitHub() {
  var result = {
    success: false,
    proxies: [],
    lastUpdate: new Date().toISOString(),
    source: 'github',
    count: 0,
    error: null,
    kvSaved: false
  };
  
  var mirrors = CONFIG.GITHUB_MIRRORS || [];
  var lastError = null;
  
  for (var i = 0; i < mirrors.length; i++) {
    try {
      var url = mirrors[i] + (mirrors[i].indexOf('?') === -1 ? '?' : '&') + 't=' + Date.now();
      
      var response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/plain,*/*',
          'Cache-Control': 'no-cache'
        }
      });
      
      if (!response.ok) {
        throw new Error('Mirror ' + (i+1) + ' returned status ' + response.status);
      }
      
      var text = await response.text();
      var proxies = parseProxyList(text);
      
      if (proxies.length === 0) {
        throw new Error('No valid proxies in mirror ' + (i+1));
      }
      
      result.proxies = proxies;
      result.count = proxies.length;
      result.success = true;
      result.source = 'github_mirror_' + (i+1);
      
      var proxyData = {
        proxies: proxies,
        lastUpdate: result.lastUpdate,
        source: result.source,
        count: proxies.length
      };
      
      result.kvSaved = await kvPut(CONFIG.KV_KEY_PROXIES, proxyData, { expirationTtl: 86400 });
      
      return result;
      
    } catch (error) {
      lastError = error.message;
      continue;
    }
  }
  
  result.error = lastError || 'All mirrors failed';
  result.proxies = FALLBACK_PROXIES;
  result.source = 'fallback';
  result.count = FALLBACK_PROXIES.length;
  return result;
}

// ==================== 解析代理列表 ====================
function parseProxyList(text) {
  var lines = text.split('\n');
  var proxies = [];
  
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) continue;
    
    var match = line.match(/^([\d.]+)#(\w+)$/);
    if (match) {
      proxies.push({ ip: match[1], region: match[2] });
      continue;
    }
    
    var cleanLine = line.replace(/\s+/g, '');
    var ipMatch = cleanLine.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (ipMatch) {
      var ip = ipMatch[1];
      var region = guessRegionByIP(ip);
      proxies.push({ ip: ip, region: region });
    }
  }
  
  return proxies;
}

// ==================== 根据 IP 段猜测地区 ====================
function guessRegionByIP(ip) {
  var firstOctet = parseInt(ip.split('.')[0], 10);
  var prefix = ip.split('.').slice(0, 2).join('.');
  
  var regionMap = {
    '8.212': 'HK', '8.219': 'SG', '47.74': 'SG', '47.242': 'HK', '47.254': 'US',
    '144.24': 'KR', '152.67': 'KR', '152.70': 'KR', '150.230': 'JP',
    '141.144': 'NL', '141.147': 'JP', '143.47': 'NL', '168.138': 'SG',
    '129.154': 'KR', '132.226': 'BR', '158.180': 'KR', '146.56': 'KR',
    '104.16': 'CF', '104.17': 'CF', '104.19': 'CF'
  };
  
  if (regionMap[prefix]) {
    return regionMap[prefix];
  }
  
  if (firstOctet === 104) {
    return 'CF';
  }
  
  return 'XX';
}

// ==================== API 处理函数 ====================
async function handleRefreshAPI(url) {
  var result = await refreshFromGitHub();
  
  return jsonResponse({
    success: result.success,
    message: result.success ? '刷新成功！' : '刷新失败，已使用备用节点',
    data: {
      source: result.source,
      count: result.count,
      lastUpdate: result.lastUpdate,
      kvSaved: result.kvSaved,
      error: result.error
    },
    preview: result.proxies.slice(0, 5)
  });
}

async function handleUploadAPI(request) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }
  
  try {
    var body = await request.json();
    
    if (body.secret !== CONFIG.UPLOAD_SECRET) {
      return jsonResponse({ error: '密钥错误' }, 403);
    }
    
    if (!body.data || typeof body.data !== 'string') {
      return jsonResponse({ error: '缺少 data 字段' }, 400);
    }
    
    var proxies = parseProxyList(body.data);
    
    if (proxies.length === 0) {
      return jsonResponse({ error: '未解析到有效代理' }, 400);
    }
    
    var proxyData = {
      proxies: proxies,
      lastUpdate: new Date().toISOString(),
      source: 'manual_upload',
      count: proxies.length
    };
    
    var saved = await kvPut(CONFIG.KV_KEY_PROXIES, proxyData, { expirationTtl: 86400 * 7 });
    
    return jsonResponse({
      success: true,
      message: '上传成功！',
      count: proxies.length,
      kvSaved: saved,
      preview: proxies.slice(0, 5)
    });
    
  } catch (e) {
    return jsonResponse({ error: '解析错误: ' + e.message }, 400);
  }
}

async function handleProxyListAPI() {
  var data = await getProxyStatus();
  return jsonResponse(data);
}

async function handleHealthAPI() {
  var health = await kvGet(CONFIG.KV_KEY_HEALTH) || {};
  return jsonResponse({
    status: 'ok',
    proxyHealth: health,
    timestamp: new Date().toISOString()
  });
}

async function handleKVDebugAPI() {
  var kvAvailable = typeof PROXY_KV !== 'undefined';
  var proxiesData = null;
  var healthData = null;
  
  if (kvAvailable) {
    proxiesData = await kvGet(CONFIG.KV_KEY_PROXIES);
    healthData = await kvGet(CONFIG.KV_KEY_HEALTH);
  }
  
  return jsonResponse({
    kvAvailable: kvAvailable,
    config: {
      githubMirrors: CONFIG.GITHUB_MIRRORS,
      blockedDomainsCount: CONFIG.PROXY_CONFIG.BLOCKED_DOMAINS.length
    },
    data: {
      proxies: proxiesData ? {
        source: proxiesData.source,
        count: proxiesData.count,
        lastUpdate: proxiesData.lastUpdate,
        sampleProxies: proxiesData.proxies ? proxiesData.proxies.slice(0, 5) : []
      } : null,
      health: healthData
    },
    timestamp: new Date().toISOString()
  });
}

// ==================== 地区优选 ====================
function selectProxiesByRegion(proxies, clientCountry, limit) {
  var maxLimit = limit || 5;
  var priorities = CONFIG.REGION_PRIORITY.DEFAULT;
  
  if (['CN', 'HK', 'TW', 'MO'].indexOf(clientCountry) !== -1) {
    priorities = CONFIG.REGION_PRIORITY.CN;
  } else if (['US', 'CA', 'MX', 'BR', 'AR'].indexOf(clientCountry) !== -1) {
    priorities = CONFIG.REGION_PRIORITY.US;
  } else if (['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'SE'].indexOf(clientCountry) !== -1) {
    priorities = CONFIG.REGION_PRIORITY.EU;
  } else if (['JP', 'KR', 'SG', 'IN', 'AU', 'TH', 'VN'].indexOf(clientCountry) !== -1) {
    priorities = CONFIG.REGION_PRIORITY.ASIA;
  }
  
  var sorted = proxies.slice().sort(function(a, b) {
    var aIdx = priorities.indexOf(a.region);
    var bIdx = priorities.indexOf(b.region);
    var aPriority = aIdx === -1 ? 999 : aIdx;
    var bPriority = bIdx === -1 ? 999 : bIdx;
    return aPriority - bPriority;
  });
  
  return sorted.slice(0, maxLimit);
}

// ==================== 工具函数 ====================
function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// ==================== 根页面 ====================
async function handleRootPage(clientIP, clientCountry) {
  var proxyStatus = await getProxyStatus();
  var recommendedProxies = selectProxiesByRegion(proxyStatus.proxies, clientCountry, 5);
  var kvAvailable = typeof PROXY_KV !== 'undefined';
  
  var html = generateInfoPage(clientIP, clientCountry, proxyStatus, recommendedProxies, kvAvailable, proxyStatus.proxies);
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function generateInfoPage(clientIP, clientCountry, proxyStatus, recommendedProxies, kvAvailable, allProxies) {
  var regionNames = {
    'SG': '🇸🇬 新加坡', 'HK': '🇭🇰 香港', 'JP': '🇯🇵 日本', 'KR': '🇰🇷 韩国',
    'US': '🇺🇸 美国', 'DE': '🇩🇪 德国', 'NL': '🇳🇱 荷兰', 'GB': '🇬🇧 英国',
    'FR': '🇫🇷 法国', 'AU': '🇦🇺 澳大利亚', 'IN': '🇮🇳 印度', 'BR': '🇧🇷 巴西',
    'SE': '🇸🇪 瑞典', 'IT': '🇮🇹 意大利', 'CN': '🇨🇳 中国', 'TW': '🇹🇼 台湾',
    'CF': '☁️ Cloudflare', 'XX': '🌐 未知'
  };
  
  function getFlag(code) {
    return regionNames[code] || ('🌐 ' + code);
  }
  
  var sourceLabel = {
    'github': '📦 GitHub',
    'github_mirror_1': '📦 GitHub镜像1',
    'github_mirror_2': '📦 GitHub镜像2',
    'github_mirror_3': '📦 GitHub镜像3',
    'github_mirror_4': '📦 GitHub镜像4',
    'manual_upload': '📤 手动上传',
    'fallback': '💾 本地缓存'
  };
  
  var proxyRows = '';
  for (var i = 0; i < recommendedProxies.length; i++) {
    var p = recommendedProxies[i];
    proxyRows += '<tr><td>' + (i+1) + '</td><td><code>' + p.ip + '</code></td><td>' + getFlag(p.region) + '</td><td><span class="badge">推荐</span></td></tr>';
  }
  
  var allRows = '';
  var displayProxies = allProxies.slice(0, 50); // 最多显示50个
  for (var j = 0; j < displayProxies.length; j++) {
    var px = displayProxies[j];
    allRows += '<tr><td>' + (j+1) + '</td><td><code>' + px.ip + '</code></td><td>' + getFlag(px.region) + '</td></tr>';
  }

  var html = '<!DOCTYPE html><html lang="zh-CN"><head>';
  html += '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
  html += '<title>Smart Proxy Gateway</title>';
  html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(135deg,#0f0f23 0%,#1a1a3e 50%,#0f0f23 100%);min-height:100vh;color:#e4e4e7;padding:2rem}.container{max-width:1200px;margin:0 auto}h1{text-align:center;font-size:2.5rem;margin-bottom:0.5rem;background:linear-gradient(90deg,#00d4ff,#7b2dff,#ff2d7b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.subtitle{text-align:center;color:#9ca3af;margin-bottom:2rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:1.5rem;margin-bottom:2rem}.card{background:rgba(30,41,59,0.6);backdrop-filter:blur(10px);border-radius:16px;padding:1.5rem;border:1px solid rgba(99,102,241,0.2)}.card h2{font-size:1.1rem;margin-bottom:1rem;color:#a5b4fc}.ip-box{background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:1.5rem;border-radius:12px;text-align:center;margin-bottom:1rem}.ip-box .label{font-size:0.85rem;opacity:0.8}.ip-box .value{font-size:1.8rem;font-weight:700;font-family:monospace}.info-row{display:flex;justify-content:space-between;padding:0.6rem 0;border-bottom:1px solid rgba(255,255,255,0.1)}.info-row:last-child{border:none}table{width:100%;border-collapse:collapse}th,td{padding:0.75rem;text-align:left;border-bottom:1px solid #334155}th{color:#9ca3af;font-size:0.8rem;text-transform:uppercase}code{background:rgba(99,102,241,0.2);padding:0.2rem 0.5rem;border-radius:4px;font-size:0.85rem}.badge{background:rgba(16,185,129,0.2);color:#10b981;padding:0.2rem 0.6rem;border-radius:12px;font-size:0.75rem}.btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;border:none;padding:0.75rem 1.5rem;border-radius:8px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block;margin:0.25rem;transition:all 0.2s}.btn:hover{transform:translateY(-2px);box-shadow:0 4px 20px rgba(99,102,241,0.4)}.btn-group{display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem}.try-box{background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);padding:1rem;border-radius:8px;margin-top:1rem}.try-box input{width:100%;padding:0.75rem;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e4e4e7;font-family:monospace;margin-bottom:0.5rem}.try-box input:focus{outline:none;border-color:#6366f1}.example{background:#1e293b;padding:1rem;border-radius:8px;margin:0.75rem 0;font-family:monospace;font-size:0.9rem;overflow-x:auto;border-left:3px solid #6366f1}.comment{color:#6b7280}.warning{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:0.75rem 1rem;border-radius:8px;margin-top:1rem;font-size:0.9rem}.protocol-hint{background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);padding:0.75rem 1rem;border-radius:8px;margin-top:0.75rem;font-size:0.85rem}</style></head><body>';
  
  html += '<div class="container">';
  html += '<h1>🌐 Smart Proxy Gateway</h1>';
  html += '<p class="subtitle">智能反向代理网关 · 支持 HTTP/HTTPS · 自定义端口</p>';
  
  html += '<div class="grid">';
  html += '<div class="card"><h2>👤 访问者信息</h2>';
  html += '<div class="ip-box"><div class="label">您的 IP 地址</div><div class="value">' + clientIP + '</div></div>';
  html += '<div class="info-row"><span>地区</span><span>' + getFlag(clientCountry) + '</span></div>';
  html += '<div class="info-row"><span>时间</span><span>' + new Date().toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'}) + '</span></div>';
  html += '</div>';
  
  html += '<div class="card"><h2>🌐 服务状态</h2>';
  html += '<div class="info-row"><span>KV 存储</span><span>' + (kvAvailable ? '✅ 已连接' : '❌ 未绑定') + '</span></div>';
  html += '<div class="info-row"><span>数据来源</span><span>' + (sourceLabel[proxyStatus.source] || proxyStatus.source) + '</span></div>';
  // 【修复】显示实际的节点数量
  html += '<div class="info-row"><span>节点数量</span><span>' + proxyStatus.count + ' 个</span></div>';
  html += '<div class="info-row"><span>更新时间</span><span style="font-size:0.75rem">' + (proxyStatus.lastUpdate || 'N/A') + '</span></div>';
  html += '<div class="btn-group"><a href="/upload" class="btn">📤 管理节点</a></div>';
  html += '</div></div>';
  
  html += '<div class="card"><h2>🚀 使用方法</h2>';
  html += '<p style="color:#9ca3af;margin-bottom:1rem">支持 HTTPS（默认）和 HTTP 协议，支持自定义端口</p>';
  html += '<h3 style="color:#a5f3fc;margin:1rem 0 0.5rem">格式说明</h3>';
  html += '<div class="example">';
  html += '<span class="comment">// HTTPS 代理（默认，可省略协议）</span><br>';
  html += '<code>https://本站域名/<strong>目标域名</strong>/路径</code><br><br>';
  html += '<span class="comment">// HTTP 代理（需显式指定完整协议）</span><br>';
  html += '<code>https://本站域名/<strong>http://目标域名</strong>/路径</code><br><br>';
  html += '<span class="comment">// 带端口的 HTTP 代理</span><br>';
  html += '<code>https://本站域名/<strong>http://目标域名:端口</strong>/路径</code><br><br>';
  html += '<span class="comment">// 带端口的代理（非443端口自动使用HTTP）</span><br>';
  html += '<code>https://本站域名/<strong>目标域名:端口</strong>/路径</code>';
  html += '</div>';
  
  html += '<div class="protocol-hint">';
  html += '💡 <strong>智能协议选择：</strong><br>';
  html += '• 端口 443 或无端口 → 默认 HTTPS<br>';
  html += '• 端口 80 或其他端口 → 默认 HTTP<br>';
  html += '• 可用 <code>http://</code> 或 <code>https://</code> 前缀强制指定协议';
  html += '</div>';
  
  html += '<div class="try-box">';
  html += '<strong style="color:#10b981">🧪 在线测试</strong>';
  html += '<input type="text" id="testUrl" placeholder="输入目标地址，例如：example.com 或 http://example.com:8080">';
  html += '<button class="btn" id="testBtn">🚀 立即测试</button>';
  html += '</div>';
  
  html += '<div class="warning">⚠️ Google、YouTube、Facebook、Twitter 等大型网站有反代理保护，无法正常使用</div>';
  html += '</div>';
  
  html += '<div class="card"><h2>⭐ 推荐节点（基于您的位置：' + getFlag(clientCountry) + '）</h2>';
  html += '<table><thead><tr><th>#</th><th>IP</th><th>地区</th><th>状态</th></tr></thead>';
  html += '<tbody>' + proxyRows + '</tbody></table></div>';
  
  html += '<div class="card"><h2>📋 全部节点（共 ' + proxyStatus.count + ' 个' + (proxyStatus.count > 50 ? '，显示前50个' : '') + '）</h2>';
  html += '<table><thead><tr><th>#</th><th>IP</th><th>地区</th></tr></thead>';
  html += '<tbody>' + allRows + '</tbody></table></div>';
  
  html += '</div>';
  
  html += '<script>document.getElementById("testBtn").onclick=function(){var u=document.getElementById("testUrl").value.trim();if(!u){alert("请输入目标域名");return;}window.open("/"+u,"_blank");};document.getElementById("testUrl").onkeypress=function(e){if(e.key==="Enter"){document.getElementById("testBtn").onclick();}};</script>';
  
  html += '</body></html>';
  
  return html;
}

// ==================== 上传页面 ====================
function handleUploadPage() {
  var html = '<!DOCTYPE html><html lang="zh-CN"><head>';
  html += '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
  html += '<title>代理列表管理</title>';
  html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);min-height:100vh;color:#e4e4e7;padding:2rem}.container{max-width:900px;margin:0 auto}h1{text-align:center;font-size:2rem;margin-bottom:0.5rem;background:linear-gradient(90deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.subtitle{text-align:center;color:#9ca3af;margin-bottom:2rem}.card{background:rgba(30,41,59,0.8);border-radius:16px;padding:1.5rem;border:1px solid #334155;margin-bottom:1.5rem}.card h2{font-size:1.1rem;margin-bottom:1rem}label{display:block;margin-bottom:0.5rem;color:#9ca3af;font-size:0.9rem}input,textarea{width:100%;padding:0.75rem;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e4e4e7;font-family:monospace;font-size:0.9rem}input:focus,textarea:focus{outline:none;border-color:#6366f1}textarea{min-height:250px;resize:vertical}.btn{background:#6366f1;color:white;border:none;padding:0.875rem 1.5rem;border-radius:8px;cursor:pointer;font-weight:600;font-size:0.95rem;transition:all 0.2s}.btn:hover{background:#4f46e5;transform:translateY(-1px)}.btn-group{display:flex;gap:0.75rem;flex-wrap:wrap;margin-top:1rem}.result{margin-top:1rem;padding:1rem;border-radius:8px;display:none;font-size:0.9rem}.result.show{display:block}.result.success{background:rgba(16,185,129,0.15);border:1px solid #10b981}.result.error{background:rgba(239,68,68,0.15);border:1px solid #ef4444}.result pre{background:#1e293b;padding:0.75rem;border-radius:6px;overflow-x:auto;margin-top:0.5rem;font-size:0.8rem}.info-box{background:rgba(99,102,241,0.1);padding:1rem;border-radius:8px;margin-bottom:1rem;font-size:0.9rem;line-height:1.6}.info-box code{background:rgba(99,102,241,0.2);padding:0.15rem 0.4rem;border-radius:4px;font-size:0.85rem}.method-tabs{display:flex;gap:0;margin-bottom:1rem}.method-tab{padding:0.75rem 1.25rem;background:#1e293b;border:1px solid #334155;cursor:pointer;font-size:0.9rem;transition:all 0.2s}.method-tab:first-child{border-radius:8px 0 0 8px}.method-tab:last-child{border-radius:0 8px 8px 0}.method-tab.active{background:#6366f1;border-color:#6366f1}.method-content{display:none}.method-content.active{display:block}.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}.status-dot.green{background:#10b981}.status-dot.red{background:#ef4444}.back-link{color:#8b5cf6;text-decoration:none}.back-link:hover{text-decoration:underline}</style></head><body>';
  
  html += '<div class="container">';
  html += '<h1>📤 代理列表管理</h1>';
  html += '<p class="subtitle">支持自动拉取与手动上传</p>';
  
  html += '<div class="card">';
  html += '<div class="method-tabs">';
  html += '<div class="method-tab active" id="tab0">🔄 自动刷新</div>';
  html += '<div class="method-tab" id="tab1">📋 手动上传</div>';
  html += '</div>';
  
  html += '<div id="method0" class="method-content active">';
  html += '<div class="info-box"><strong>🔄 自动刷新说明：</strong><br><br>从 GitHub 仓库获取最新代理列表。<br><br><strong>数据源：</strong> GitHub Raw（多镜像）</div>';
  html += '<div class="btn-group"><button class="btn" id="refreshBtn">🔄 从 GitHub 刷新</button></div>';
  html += '</div>';
  
  html += '<div id="method1" class="method-content">';
  html += '<div class="info-box"><strong>📋 手动上传说明：</strong><br><br>格式：每行一个 <code>IP#地区</code>，例如：<code>47.74.157.194#SG</code></div>';
  html += '<label for="secret">🔑 上传密钥</label>';
  html += '<input type="password" id="secret" placeholder="输入 UPLOAD_SECRET">';
  html += '<label for="proxyData" style="margin-top:1rem">📋 代理列表</label>';
  html += '<textarea id="proxyData" placeholder="47.74.157.194#SG\n8.212.12.98#HK"></textarea>';
  html += '<div class="btn-group"><button class="btn" id="uploadBtn">🚀 上传</button></div>';
  html += '</div>';
  
  html += '<div id="result" class="result"></div>';
  html += '</div>';
  
  html += '<div class="card"><h2>📊 当前状态</h2><div id="statusContent">加载中...</div></div>';
  html += '<div class="card"><a href="/" class="back-link">← 返回主页</a></div>';
  html += '</div>';
  
  html += '<script>';
  html += 'var tab0=document.getElementById("tab0"),tab1=document.getElementById("tab1"),m0=document.getElementById("method0"),m1=document.getElementById("method1");';
  html += 'tab0.onclick=function(){tab0.className="method-tab active";tab1.className="method-tab";m0.className="method-content active";m1.className="method-content";};';
  html += 'tab1.onclick=function(){tab1.className="method-tab active";tab0.className="method-tab";m1.className="method-content active";m0.className="method-content";};';
  
  html += 'document.getElementById("refreshBtn").onclick=async function(){var r=document.getElementById("result");r.className="result show";r.innerHTML="⏳ 刷新中...";try{var res=await fetch("/api/refresh");var d=await res.json();if(d.success){r.className="result show success";r.innerHTML="✅ "+d.message+"<br>来源: "+d.data.source+"<br>数量: "+d.data.count+"<pre>"+JSON.stringify(d.preview,null,2)+"</pre>";loadStatus();}else{r.className="result show error";r.innerHTML="❌ "+d.message+"<br>"+(d.data.error||"");}}catch(e){r.className="result show error";r.innerHTML="❌ "+e.message;}};';
  
  html += 'document.getElementById("uploadBtn").onclick=async function(){var secret=document.getElementById("secret").value.trim();var data=document.getElementById("proxyData").value.trim();var r=document.getElementById("result");if(!secret||!data){r.className="result show error";r.textContent="请填写完整";return;}r.className="result show";r.innerHTML="⏳ 上传中...";try{var res=await fetch("/api/upload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({secret:secret,data:data})});var d=await res.json();if(d.success){r.className="result show success";r.innerHTML="✅ "+d.message+"<br>数量: "+d.count+"<pre>"+JSON.stringify(d.preview,null,2)+"</pre>";loadStatus();}else{r.className="result show error";r.textContent="❌ "+d.error;}}catch(e){r.className="result show error";r.textContent="❌ "+e.message;}};';
  
  html += 'async function loadStatus(){try{var res=await fetch("/api/kv-debug");var d=await res.json();var p=d.data.proxies;document.getElementById("statusContent").innerHTML="<div style=\\"display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem\\"><div><span style=\\"color:#9ca3af\\">KV</span><br><span class=\\"status-dot "+(d.kvAvailable?"green":"red")+"\\"></span> "+(d.kvAvailable?"已连接":"未绑定")+"</div>"+(p?"<div><span style=\\"color:#9ca3af\\">来源</span><br>"+p.source+"</div><div><span style=\\"color:#9ca3af\\">数量</span><br>"+p.count+"</div>":"")+"</div>";}catch(e){document.getElementById("statusContent").innerHTML="❌ "+e.message;}}loadStatus();';
  html += '</script>';
  
  html += '</body></html>';
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

