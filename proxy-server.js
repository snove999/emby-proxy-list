const http = require('http');
const httpProxy = require('http-proxy');
const { URL } = require('url');

// --- 配置部分 ---
const CONFIG = {
  LISTEN_PORT: 3000, // Node.js 监听的本地端口
  BLOCKED_DOMAINS: [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com'
  ],
  MEDIA_PATTERNS: [
    '/emby/', '/jellyfin/', '/mediabrowser/', '/videos/', '/Audio/', '/socket', '/embywebsocket'
  ],
  REMOVE_HEADERS: ['content-security-policy', 'x-frame-options']
};

// 创建代理实例
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  ws: true // 开启 WebSocket 支持
});

// 错误处理：防止目标服务器宕机导致 Node 进程崩溃
proxy.on('error', (err, req, res) => {
  console.error('Proxy Error:', err.message);
  if (res.writeHead) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad Gateway: Target is unreachable');
  }
});

// 响应拦截：处理特定的 Header（如移除 CSP）
proxy.on('proxyRes', (proxyRes, req, res) => {
  CONFIG.REMOVE_HEADERS.forEach(header => {
    delete proxyRes.headers[header];
  });
  // 允许跨域
  proxyRes.headers['Access-Control-Allow-Origin'] = '*';
});

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.slice(1); // 获取域名部分，例如 "example.com:8096/path"
  
  // 1. 首页逻辑
  if (req.url === '/' || req.url === '') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end('<h1>Proxy Server is Running</h1><p>使用方式: https://你的域名/目标域名:端口</p>');
  }

  // 2. 解析目标 URL
  let targetUrl;
  try {
    // 提取第一个斜杠前的部分作为 host
    const firstSlash = urlPath.indexOf('/');
    const hostPart = firstSlash === -1 ? urlPath : urlPath.substring(0, firstSlash);
    const remainPath = firstSlash === -1 ? '' : urlPath.substring(firstSlash);
    
    // 简单的协议判断：如果是 443 或包含 https:// 则用 https
    const protocol = hostPart.includes('443') ? 'https://' : 'http://';
    targetUrl = protocol + hostPart;
    
    // 构造新的请求路径
    req.url = remainPath || '/';
  } catch (e) {
    res.writeHead(400);
    return res.end('Invalid Target');
  }

  // 3. 域名黑名单检查
  const hostname = new URL(targetUrl).hostname;
  if (CONFIG.BLOCKED_DOMAINS.some(d => hostname.endsWith(d))) {
    res.writeHead(403);
    return res.end('Domain Blocked');
  }

  // 4. 执行转发
  console.log(`Proxying: ${req.method} ${targetUrl}${req.url}`);
  proxy.web(req, res, { target: targetUrl });
});

// 5. 处理 WebSocket 转发 (Emby 核心需求)
server.on('upgrade', (req, socket, head) => {
  const urlPath = req.url.slice(1);
  const firstSlash = urlPath.indexOf('/');
  const hostPart = firstSlash === -1 ? urlPath : urlPath.substring(0, firstSlash);
  const protocol = hostPart.includes('443') ? 'https://' : 'http://';
  
  req.url = firstSlash === -1 ? '/' : urlPath.substring(firstSlash);
  
  proxy.ws(req, socket, head, { target: protocol + hostPart });
});

server.listen(CONFIG.LISTEN_PORT, () => {
  console.log(`Node.js Proxy running on port ${CONFIG.LISTEN_PORT}`);
});