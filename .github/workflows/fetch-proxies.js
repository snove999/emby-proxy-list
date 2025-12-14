name: Fetch Proxy List

on:
  schedule:
    # 每小时执行
    - cron: '0 * * * *'
  workflow_dispatch:

jobs:
  fetch:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: npm install puppeteer
      
      - name: Fetch proxy list
        run: |
          cat << 'SCRIPT' > fetch.js
          const puppeteer = require('puppeteer');
          const fs = require('fs');

          const MAX_RETRIES = 3;
          const WAIT_TIMES = [10000, 15000, 20000]; // 递增等待时间

          async function fetchProxies(retryCount = 0) {
            console.log(`\n========== 第 ${retryCount + 1} 次尝试 ==========`);
            
            const browser = await puppeteer.launch({
              headless: 'new',
              args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
              ]
            });
            
            try {
              const page = await browser.newPage();
              
              // 设置更真实的浏览器环境
              await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
              await page.setViewport({ width: 1920, height: 1080 });
              
              // 设置额外的 headers
              await page.setExtraHTTPHeaders({
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
              });
              
              console.log('访问目标页面...');
              
              // 访问页面
              await page.goto('https://ipdb.api.030101.xyz/?type=bestproxy&country=true', {
                waitUntil: 'domcontentloaded',
                timeout: 30000
              });
              
              // 等待 Cloudflare 验证（递增等待时间）
              const waitTime = WAIT_TIMES[retryCount] || 20000;
              console.log(`等待 Cloudflare 验证 ${waitTime/1000} 秒...`);
              await new Promise(r => setTimeout(r, waitTime));
              
              // 检查是否还在验证页面
              const pageTitle = await page.title();
              console.log('页面标题:', pageTitle);
              
              if (pageTitle.includes('moment') || pageTitle.includes('Cloudflare')) {
                console.log('仍在验证页面，继续等待...');
                await new Promise(r => setTimeout(r, 10000));
              }
              
              // 等待网络空闲
              try {
                await page.waitForNetworkIdle({ timeout: 10000 });
              } catch (e) {
                console.log('网络未完全空闲，继续处理...');
              }
              
              // 获取页面内容
              const content = await page.evaluate(() => {
                // 尝试获取 pre 标签内容（如果API返回纯文本）
                const pre = document.querySelector('pre');
                if (pre) return pre.innerText;
                return document.body.innerText;
              });
              
              console.log('获取到内容长度:', content.length);
              console.log('内容预览:', content.substring(0, 200));
              
              // 解析代理列表
              const lines = content.trim().split('\n').filter(line => {
                const trimmed = line.trim();
                return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#[A-Z]{2}$/i.test(trimmed);
              });
              
              console.log('解析到代理数量:', lines.length);
              
              if (lines.length >= 1) {
                // 成功获取足够数量的代理
                fs.writeFileSync('proxies.txt', lines.join('\n'));
                console.log('\n✅ 成功！获取到', lines.length, '个代理');
                console.log('前10个:', lines.slice(0, 10));
                return true;
              } else if (lines.length > 0) {
                console.log('⚠️ 获取到部分代理:', lines);
              }
              
              // 代理数量不足，尝试重试
              if (retryCount < MAX_RETRIES - 1) {
                console.log('代理数量不足，准备重试...');
                await browser.close();
                return fetchProxies(retryCount + 1);
              }
              
              // 最后一次尝试，即使数量少也保存
              if (lines.length > 0) {
                fs.writeFileSync('proxies.txt', lines.join('\n'));
                console.log('\n⚠️ 仅获取到', lines.length, '个代理，已保存');
                return true;
              }
              
              console.log('\n❌ 未能获取到有效代理');
              return false;
              
            } finally {
              await browser.close();
            }
          }

          // 执行
          fetchProxies().then(success => {
            if (!success) {
              console.log('\n所有尝试均失败，保留原有文件');
            }
          }).catch(error => {
            console.error('执行错误:', error);
            process.exit(1);
          });
          SCRIPT
          
          node fetch.js
      
      - name: Verify result
        run: |
          echo "========== 验证结果 =========="
          if [ -f proxies.txt ]; then
            echo "文件大小: $(wc -c < proxies.txt) 字节"
            echo "代理数量: $(wc -l < proxies.txt) 行"
            echo ""
            echo "=== 文件内容 ==="
            cat proxies.txt
          else
            echo "❌ proxies.txt 不存在"
            exit 1
          fi
      
      - name: Commit and push
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action Bot"
          git add proxies.txt
          
          if git diff --staged --quiet; then
            echo "✅ 文件无变化，无需提交"
          else
            PROXY_COUNT=$(wc -l < proxies.txt)
            git commit -m "🔄 Update proxies: ${PROXY_COUNT} nodes [$(date -u +'%Y-%m-%d %H:%M UTC')]"
            git push
            echo "✅ 已提交更新"
          fi
