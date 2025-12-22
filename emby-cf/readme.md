# 使用 Cloudflare Workers反向代理网站

### 1. 准备工作
*   一个 **Cloudflare 账号**。
*   一个 **自定义域名** 并已托管在 Cloudflare 上。

### 2. 创建 Cloudflare Worker
1.  登录 [Cloudflare 控制台](https://dash.cloudflare.com/)。
2.  在左侧菜单栏点击 **Compute & AI（计算和AI）** > **Workers & Pages**。
3.  点击 **Create application（创建应用程序）** > **Start with Hello World!**。
4.  为你的 Worker 起一个名字（例如 `fallback-proxy`），然后点击 **Deploy（部署）**。
5.  部署完成后，点击 **Edit Code（编辑代码）**。

### 3. 配置脚本
1.  打开 GitHub 上的 [脚本](https://raw.githubusercontent.com/snove999/emby-proxy-list/refs/heads/main/emby-cf/emby-cf.js) 文件。
2.  复制该文件的全部代码。
3.  回到 Cloudflare Worker 的代码编辑器，清空原有代码，并将复制的代码 **粘贴** 进去。
4.  点击**Deploy（部署）**。

### 4. KV空间配置
1.  打开[Cloudflare 控制台](https://dash.cloudflare.com/)。
2.  在左侧菜单栏点击 **Storage & databases（存储和数据库）** > **Workers KV**。
3.  点击 **Create Instance（创建应用程序）**。
4.  **Namespace name（命名空间名称）** 输入 **PROXY_KV** > **Create（创建）**

### 5. 绑定KV空间
1.  在 Worker 的管理界面，点击 **Binding（绑定）** 选项卡。
2.  点击 **Add binding（添加绑定）** > **KV namespace（KV 命名空间）** > **Variable name（变量名称）填写PROXY_KV** > **KV namespace（KV 命名空间）选择PROXY_KV** > ***Add binding（添加绑定）**。

### 6. 绑定自定义域名（强烈推荐）
由于 `workers.dev` 域名在某些地区访问不稳定，建议绑定自己的域名：
1.  在 Worker 的管理界面，点击 **Settings（设置）** 选项卡。
2.  点击 **Domains & Routes（域和路由）** > **Add（添加）**
3.  在 **Custom Domain（自定义域）** 栏目下，输入你自己的子域名（例如 `yourdomain.com`），Cloudflare 会自动处理 DNS 和 SSL 证书。
