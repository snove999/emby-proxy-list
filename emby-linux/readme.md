### 第一步：Node.js 完善

首先，在你的 Linux 目录中初始化并安装依赖：
```bash
sudo npm init -y
sudo apt update
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs git
```

---

### 然后下载并进入你存放项目的目录

```bash
npx degit snove999/emby-proxy-list/emby-linux emby-linux
cd emby-linux
npm install
```
---

### 第二步：Nginx 配置与 SSL

#### 1. 获取 SSL 证书 (使用 Certbot)
```bash
sudo apt update
sudo ln -s /etc/nginx/sites-available/emby-proxy /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
sudo apt install -y certbot python3-certbot-nginx
# 按照提示操作，它会自动修改 Nginx 配置
sudo certbot --nginx -d 你的域名.com
```

#### 2. 完善 Nginx 配置文件
编辑你的域名配置文件 `sudo nanao /etc/nginx/sites-available/emby-proxy`

```nginx
server {
    listen 80;
    server_name 你的域名.com;
    return 301 https://$host$request_uri; # 强制跳转 HTTPS
}

server {
    listen 443 ssl http2;
    server_name 你的域名.com;

    # SSL 证书路径 (Certbot 会自动生成)
    ssl_certificate /etc/letsencrypt/live/你的域名.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/你的域名.com/privkey.pem;

    # 性能优化
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        # 转发到 Node.js 服务
        proxy_pass http://127.0.0.1:3000;
        
        # 必须：传递真实的客户端信息
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 必须：支持 WebSocket 转发
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # 针对流媒体的优化：关闭缓存，允许大文件传输
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 0; # 解除上传大小限制
    }
}
```
修改完后重启 Nginx: `sudo systemctl restart nginx`

---

### 第三步：Linux 部署与维护

1.  **使用 PM2 守护进程**：
    为了保证 Node.js 程序在后台运行且崩溃后自动重启：
    ```bash
    sudo npm install pm2 -g
    pm2 start proxy-server.js --name "emby-proxy"
    pm2 save
    pm2 startup
    ```

2.  **防火墙设置**：
    确保 Linux 只开放 80 和 443 端口，3000 端口留在内部访问即可。
    ```bash
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw enable
    ```
