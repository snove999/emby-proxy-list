import os
import re
import csv
import json
import time
import asyncio
import socket
from datetime import datetime, timezone
from typing import Set, Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import logging

import requests
from bs4 import BeautifulSoup

# ============================================================
# 配置
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# 环境变量配置
SKIP_VALIDATION = os.environ.get('SKIP_VALIDATION', 'false').lower() == 'true'
VALIDATION_TIMEOUT = float(os.environ.get('VALIDATION_TIMEOUT', '3'))
VALIDATION_CONCURRENCY = int(os.environ.get('VALIDATION_CONCURRENCY', '100'))
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'output')

# ============================================================
# 数据源配置
# ============================================================

SOURCES = [
    {
        "name": "ipTop10.html",
        "url": "https://raw.githubusercontent.com/chnbsdan/cf-speed-dns/refs/heads/main/ipTop10.html",
        "type": "html",
        "category": "cloudflare"
    },
    {
        "name": "edgetunnel-output",
        "url": "https://raw.githubusercontent.com/chnbsdan/edgetunnel3/refs/heads/main/output.txt",
        "type": "text",
        "category": "cloudflare"
    },
    {
        "name": "bestproxy",
        "url": "https://ipdb.api.030101.xyz/?type=bestproxy&country=true",
        "type": "text",
        "category": "proxy"
    },
    {
        "name": "bestcf",
        "url": "https://ipdb.api.030101.xyz/?type=bestcf",
        "type": "text",
        "category": "proxy"
    },
    {
        "name": "socks5-proxy",
        "url": "https://raw.githubusercontent.com/chnbsdan/free-proxy-list/refs/heads/main/proxy.txt",
        "type": "socks5_rich",
        "category": "socks5"
    }
]

# ============================================================
# 数据结构
# ============================================================

@dataclass
class IPEntry:
    """IP 条目数据结构"""
    ip: str
    port: Optional[int] = None
    
    # 来源信息
    source: str = ""
    category: str = ""
    
    # 地理信息（从源数据或 API 获取）
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    
    # 网络类型
    net_type: str = ""  # 机房 / 家宽 / unknown
    
    # 验证结果
    is_valid: Optional[bool] = None
    latency_ms: Optional[float] = None
    validation_error: str = ""
    
    @property
    def address(self) -> str:
        """完整地址 IP:PORT"""
        if self.port:
            return f"{self.ip}:{self.port}"
        return self.ip
    
    @property
    def location(self) -> str:
        """位置简述"""
        parts = []
        if self.country:
            parts.append(self.country)
        if self.city:
            parts.append(self.city)
        elif self.region:
            parts.append(self.region)
        return " ".join(parts) if parts else "Unknown"
    
    @property
    def net_type_en(self) -> str:
        """网络类型英文"""
        mapping = {
            "机房": "datacenter",
            "家宽": "residential",
            "": "unknown"
        }
        return mapping.get(self.net_type, "unknown")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "ip": self.ip,
            "port": self.port,
            "source": self.source,
            "category": self.category,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "isp": self.isp,
            "net_type": self.net_type,
            "net_type_en": self.net_type_en,
            "location": self.location,
            "is_valid": self.is_valid,
            "latency_ms": self.latency_ms,
            "validation_error": self.validation_error
        }


# ============================================================
# 正则表达式
# ============================================================

IPV4_PATTERN = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

# 标准代理 URL 格式: protocol://IP:PORT
PROXY_URL_PATTERN = re.compile(
    r'(?:socks[45]?|https?|ss|ssr|vmess|trojan)://'
    r'(?:[^:@\s]+:[^:@\s]+@)?'  # 可选认证
    rf'({IPV4_PATTERN}):(\d{{1,5}})',
    re.IGNORECASE
)

# 富信息 SOCKS5 格式: socks5://IP:PORT [[类型] 国家 省 城市 [ISP]]
SOCKS5_RICH_PATTERN = re.compile(
    rf'socks[45]?://({IPV4_PATTERN}):(\d{{1,5}})'  # IP:PORT
    r'\s*'
    r'\[\[([^\]]*)\]\s*'  # [[类型]
    r'([^\[]*?)'  # 国家 省 城市
    r'\[([^\]]*)\]\]',  # [ISP]]
    re.IGNORECASE
)

# 备用：更宽松的富信息匹配
SOCKS5_RICH_PATTERN_ALT = re.compile(
    rf'socks[45]?://({IPV4_PATTERN}):(\d{{1,5}})'
    r'\s*\[\['
    r'(机房|家宽)'
    r'\]\s*'
    r'([^\[]+?)'
    r'\s*\[([^\]]+)\]\]',
    re.IGNORECASE
)

# IP:PORT 或 IP#PORT
LOOSE_IP_PORT_PATTERN = re.compile(rf'\b({IPV4_PATTERN})[:#](\d{{1,5}})\b')

# 纯 IP
PURE_IP_PATTERN = re.compile(rf'\b({IPV4_PATTERN})\b')


# ============================================================
# 网络工具
# ============================================================

def fetch_content(url: str, timeout: int = 30, retries: int = 3) -> str:
    """获取 URL 内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt + 1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(1)
    return ""


def tcp_ping(ip: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[float], str]:
    """TCP 连接测试"""
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        
        if result == 0:
            return True, round(elapsed, 2), ""
        return False, None, f"Connection failed (code: {result})"
    except socket.timeout:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, str(e)


async def async_tcp_ping(ip: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[float], str]:
    """异步 TCP 测试"""
    try:
        start = time.time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        elapsed = (time.time() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return True, round(elapsed, 2), ""
    except asyncio.TimeoutError:
        return False, None, "Timeout"
    except ConnectionRefusedError:
        return False, None, "Connection refused"
    except Exception as e:
        return False, None, str(e)


async def validate_entries_async(
    entries: List[IPEntry],
    timeout: float = 3.0,
    concurrency: int = 100
) -> None:
    """批量异步验证（原地修改）"""
    semaphore = asyncio.Semaphore(concurrency)
    completed = 0
    total = len(entries)
    
    async def validate_one(entry: IPEntry):
        nonlocal completed
        async with semaphore:
            if entry.port:
                success, latency, error = await async_tcp_ping(entry.ip, entry.port, timeout)
            else:
                # 无端口时测试常用端口
                success, latency, error = False, None, "No port"
                for test_port in [443, 80, 8080, 1080]:
                    success, latency, error = await async_tcp_ping(entry.ip, test_port, timeout / 4)
                    if success:
                        break
            
            entry.is_valid = success
            entry.latency_ms = latency
            entry.validation_error = error
            
            completed += 1
            if completed % 100 == 0:
                logger.info(f"   Validated: {completed}/{total}")
    
    tasks = [validate_one(e) for e in entries]
    await asyncio.gather(*tasks, return_exceptions=True)


# ============================================================
# 解析器
# ============================================================

def is_valid_ip(ip: str) -> bool:
    """验证 IPv4"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return not (ip.startswith('0.') or ip == '255.255.255.255')
    except ValueError:
        return False


def is_valid_port(port) -> bool:
    """验证端口"""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def parse_socks5_rich_line(line: str, source_name: str) -> Optional[IPEntry]:
    """
    解析富信息 SOCKS5 行
    格式: socks5://IP:PORT [[类型] 国家 省 城市 [ISP]]
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # 尝试主正则
    match = SOCKS5_RICH_PATTERN.search(line)
    if not match:
        match = SOCKS5_RICH_PATTERN_ALT.search(line)
    
    if match:
        ip, port_str, net_type, location_str, isp = match.groups()
        
        if not is_valid_ip(ip) or not is_valid_port(port_str):
            return None
        
        # 解析位置字符串: "韩国 首尔特别市 首尔特别市" 或 "意大利 普利亚"
        location_parts = location_str.strip().split()
        country = location_parts[0] if len(location_parts) > 0 else ""
        region = location_parts[1] if len(location_parts) > 1 else ""
        city = location_parts[2] if len(location_parts) > 2 else ""
        
        # 如果只有两部分，第二部分可能是城市
        if len(location_parts) == 2:
            city = region
            region = ""
        
        return IPEntry(
            ip=ip,
            port=int(port_str),
            source=source_name,
            category="socks5",
            net_type=net_type.strip(),
            country=country,
            region=region,
            city=city,
            isp=isp.strip()
        )
    
    # 回退到简单格式
    simple_match = PROXY_URL_PATTERN.search(line)
    if simple_match:
        ip, port_str = simple_match.groups()
        if is_valid_ip(ip) and is_valid_port(port_str):
            return IPEntry(
                ip=ip,
                port=int(port_str),
                source=source_name,
                category="socks5"
            )
    
    return None


def parse_simple_line(line: str, source_name: str, category: str) -> List[IPEntry]:
    """解析简单格式行（IP 或 IP:PORT）"""
    results = []
    line = line.strip()
    
    if not line or line.startswith('#'):
        return results
    
    # 尝试代理 URL
    proxy_match = PROXY_URL_PATTERN.search(line)
    if proxy_match:
        ip, port_str = proxy_match.groups()
        if is_valid_ip(ip) and is_valid_port(port_str):
            results.append(IPEntry(
                ip=ip,
                port=int(port_str),
                source=source_name,
                category=category
            ))
        return results
    
    # 尝试 IP:PORT
    for match in LOOSE_IP_PORT_PATTERN.finditer(line):
        ip, port_str = match.groups()
        if is_valid_ip(ip) and is_valid_port(port_str):
            results.append(IPEntry(
                ip=ip,
                port=int(port_str),
                source=source_name,
                category=category
            ))
    
    # 尝试纯 IP
    if not results:
        for match in PURE_IP_PATTERN.finditer(line):
            ip = match.group(1)
            if is_valid_ip(ip):
                results.append(IPEntry(
                    ip=ip,
                    source=source_name,
                    category=category
                ))
    
    return results


def parse_text_content(content: str, source_name: str, category: str) -> List[IPEntry]:
    """解析纯文本内容"""
    entries = []
    for line in content.split('\n'):
        entries.extend(parse_simple_line(line, source_name, category))
    return entries


def parse_socks5_rich_content(content: str, source_name: str) -> List[IPEntry]:
    """解析富信息 SOCKS5 内容"""
    entries = []
    for line in content.split('\n'):
        entry = parse_socks5_rich_line(line, source_name)
        if entry:
            entries.append(entry)
    return entries


def parse_html_content(content: str, source_name: str, category: str) -> List[IPEntry]:
    """解析 HTML 内容"""
    entries = []
    
    try:
        soup = BeautifulSoup(content, 'lxml')
        
        # 从表格提取
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                for cell in row.find_all(['td', 'th']):
                    text = cell.get_text(strip=True)
                    entries.extend(parse_simple_line(text, source_name, category))
        
        # 从其他标签提取
        for tag in soup.find_all(['span', 'div', 'p', 'li', 'code', 'pre']):
            text = tag.get_text(strip=True)
            entries.extend(parse_simple_line(text, source_name, category))
        
        # 兜底：纯文本
        plain_text = soup.get_text(separator='\n')
        entries.extend(parse_text_content(plain_text, source_name, category))
        
    except Exception as e:
        logger.error(f"HTML parsing error: {e}")
        entries.extend(parse_text_content(content, source_name, category))
    
    return entries


# ============================================================
# 数据源处理
# ============================================================

def process_source(source: Dict) -> List[IPEntry]:
    """处理单个数据源"""
    logger.info(f"📥 Fetching: {source['name']}")
    
    content = fetch_content(source['url'])
    if not content:
        logger.warning(f"⚠️  Empty: {source['name']}")
        return []
    
    source_type = source['type']
    source_name = source['name']
    category = source.get('category', 'unknown')
    
    if source_type == 'html':
        entries = parse_html_content(content, source_name, category)
    elif source_type == 'socks5_rich':
        entries = parse_socks5_rich_content(content, source_name)
    else:
        entries = parse_text_content(content, source_name, category)
    
    logger.info(f"✅ Found {len(entries)} entries from {source_name}")
    return entries


def deduplicate_entries(entries: List[IPEntry]) -> List[IPEntry]:
    """去重（保留信息最丰富的条目）"""
    seen: Dict[str, IPEntry] = {}
    
    for entry in entries:
        key = entry.address
        
        if key not in seen:
            seen[key] = entry
        else:
            # 保留信息更丰富的
            existing = seen[key]
            # 如果新条目有地理信息而旧的没有，替换
            if entry.country and not existing.country:
                seen[key] = entry
            # 如果新条目有网络类型而旧的没有，合并
            elif entry.net_type and not existing.net_type:
                existing.net_type = entry.net_type
                existing.country = entry.country or existing.country
                existing.region = entry.region or existing.region
                existing.city = entry.city or existing.city
                existing.isp = entry.isp or existing.isp
    
    return list(seen.values())


def sort_entries(entries: List[IPEntry]) -> List[IPEntry]:
    """排序"""
    def sort_key(entry: IPEntry):
        try:
            octets = [int(x) for x in entry.ip.split('.')]
            return (0, octets, entry.port or 0)
        except ValueError:
            return (1, [0, 0, 0, 0], 0)
    
    return sorted(entries, key=sort_key)


# ============================================================
# 导出器
# ============================================================

class Exporter:
    """多格式导出器"""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    def export_all(self, entries: List[IPEntry], stats: Dict[str, Any]):
        """导出所有格式"""
        data = [e.to_dict() for e in entries]
        
        self._export_txt(entries, stats)
        self._export_json(data, stats)
        self._export_csv(data)
        self._export_valid_only(entries)
        self._export_summary(entries, stats)
        self._export_root_txt(entries)
        
        logger.info(f"📁 Exported to {self.output_dir}/")
    
    def _export_txt(self, entries: List[IPEntry], stats: Dict):
        """导出详细 TXT"""
        filepath = os.path.join(self.output_dir, "all.txt")
        
        valid_count = sum(1 for e in entries if e.is_valid is True or e.is_valid is None)
        
        lines = [
            "# " + "=" * 70,
            "# Aggregated IP/Proxy Addresses",
            f"# Generated: {self.timestamp}",
            f"# Total: {len(entries)} | Valid: {valid_count}",
            "# " + "=" * 70,
            "# Format: ADDRESS | TYPE | LATENCY | LOCATION | ISP",
            "# " + "=" * 70,
            ""
        ]
        
        for e in entries:
            status = "✓" if e.is_valid else ("✗" if e.is_valid is False else "?")
            latency = f"{e.latency_ms:.0f}ms" if e.latency_ms else "-"
            net_type = e.net_type or "-"
            location = e.location or "-"
            isp = e.isp[:30] if e.isp else "-"
            
            lines.append(f"{e.address:<22} | {status} {net_type:<4} | {latency:<8} | {location:<20} | {isp}")
        
        lines.append("")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
    
    def _export_json(self, data: List[Dict], stats: Dict):
        """导出 JSON"""
        filepath = os.path.join(self.output_dir, "all.json")
        
        # 统计
        by_country = {}
        by_net_type = {"datacenter": 0, "residential": 0, "unknown": 0}
        by_source = {}
        
        for item in data:
            country = item.get('country') or 'Unknown'
            by_country[country] = by_country.get(country, 0) + 1
            
            net_type = item.get('net_type_en', 'unknown')
            by_net_type[net_type] = by_net_type.get(net_type, 0) + 1
            
            source = item.get('source', 'unknown')
            by_source[source] = by_source.get(source, 0) + 1
        
        # 延迟统计
        latencies = [d['latency_ms'] for d in data if d.get('latency_ms')]
        latency_stats = {}
        if latencies:
            latencies.sort()
            latency_stats = {
                "min": min(latencies),
                "max": max(latencies),
                "avg": round(sum(latencies) / len(latencies), 2),
                "median": latencies[len(latencies) // 2]
            }
        
        output = {
            "metadata": {
                "generated_at": self.timestamp,
                "total_count": len(data),
                "valid_count": sum(1 for d in data if d.get('is_valid') is True or d.get('is_valid') is None),
                "validated": not SKIP_VALIDATION
            },
            "statistics": {
                "by_country": dict(sorted(by_country.items(), key=lambda x: x[1], reverse=True)),
                "by_net_type": by_net_type,
                "by_source": by_source,
                "latency": latency_stats
            },
            "data": data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, data: List[Dict]):
        """导出 CSV"""
        filepath = os.path.join(self.output_dir, "all.csv")
        
        if not data:
            return
        
        fieldnames = [
            'address', 'ip', 'port', 'net_type', 'net_type_en',
            'country', 'region', 'city', 'isp', 'location',
            'is_valid', 'latency_ms', 'source', 'category'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(data)
    
    def _export_valid_only(self, entries: List[IPEntry]):
        """导出仅有效 IP"""
        filepath = os.path.join(self.output_dir, "valid_only.txt")
        
        valid = [e for e in entries if e.is_valid is True or e.is_valid is None]
        
        lines = [
            f"# Valid IPs - {self.timestamp}",
            f"# Count: {len(valid)}",
            ""
        ]
        lines.extend([e.address for e in valid])
        lines.append("")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
    
    def _export_summary(self, entries: List[IPEntry], stats: Dict):
        """导出 Markdown 摘要"""
        filepath = os.path.join(self.output_dir, "summary.md")
        
        total = len(entries)
        valid = sum(1 for e in entries if e.is_valid is True)
        invalid = sum(1 for e in entries if e.is_valid is False)
        untested = total - valid - invalid
        
        # 国家统计
        country_counts = {}
        for e in entries:
            c = e.country or 'Unknown'
            country_counts[c] = country_counts.get(c, 0) + 1
        top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        
        # 网络类型统计
        net_type_counts = {"机房": 0, "家宽": 0, "未知": 0}
        for e in entries:
            if e.net_type == "机房":
                net_type_counts["机房"] += 1
            elif e.net_type == "家宽":
                net_type_counts["家宽"] += 1
            else:
                net_type_counts["未知"] += 1
        
        # 最快 IP
        valid_with_latency = [e for e in entries if e.is_valid and e.latency_ms]
        fastest = sorted(valid_with_latency, key=lambda x: x.latency_ms)[:15]
        
        md = f"""# 📊 IP Aggregation Report

> **Generated:** {self.timestamp}

## 📈 Overview

| Metric | Value |
|--------|-------|
| **Total Entries** | {total} |
| **✅ Valid** | {valid} ({valid/total*100:.1f}% ) |
| **❌ Invalid** | {invalid} ({invalid/total*100:.1f}%) |
| **❓ Untested** | {untested} |

## 📡 Sources

| Source | Count |
|--------|-------|
"""
        for name, count in stats.get('sources', {}).items():
            md += f"| {name} | {count} |\n"
        
        md += f"""
## 🏠 Network Type Distribution

| Type | Count | Percentage |
|------|-------|------------|
| 🏢 机房 (Datacenter) | {net_type_counts['机房']} | {net_type_counts['机房']/total*100:.1f}% |
| 🏠 家宽 (Residential) | {net_type_counts['家宽']} | {net_type_counts['家宽']/total*100:.1f}% |
| ❓ 未知 (Unknown) | {net_type_counts['未知']} | {net_type_counts['未知']/total*100:.1f}% |

## 🌍 Geographic Distribution (Top 15)

| Country | Count | Percentage |
|---------|-------|------------|
"""
        for country, count in top_countries:
            pct = count / total * 100
            md += f"| {country} | {count} | {pct:.1f}% |\n"
        
        md += f"""
## ⚡ Top 15 Fastest IPs

| Address | Latency | Type | Location | ISP |
|---------|---------|------|----------|-----|
"""
        for e in fastest:
            net = e.net_type or "-"
            loc = e.location or "-"
            isp = (e.isp[:25] + "...") if e.isp and len(e.isp) > 25 else (e.isp or "-")
            md += f"| `{e.address}` | {e.latency_ms:.0f}ms | {net} | {loc} | {isp} |\n"
        
        md += """
---
*Auto-generated by IP Aggregation System v4.0*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)
    
    def _export_root_txt(self, entries: List[IPEntry]):
        """根目录简洁格式"""
        filepath = "all.txt"
        
        lines = [
            f"# IP List - {self.timestamp}",
            f"# Total: {len(entries)}",
            ""
        ]
        lines.extend([e.address for e in entries])
        lines.append("")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))


# ============================================================
# 主程序
# ============================================================

def main():
    """主函数"""
    start_time = time.time()
    
    logger.info("=" * 60)
    logger.info("🚀 IP Aggregation System v4.0")
    logger.info("=" * 60)
    logger.info(f"⚙️  Validation: {'SKIP' if SKIP_VALIDATION else 'ENABLED'}")
    if not SKIP_VALIDATION:
        logger.info(f"⚙️  Timeout: {VALIDATION_TIMEOUT}s | Concurrency: {VALIDATION_CONCURRENCY}")
    logger.info("=" * 60)
    
    # ===== 阶段 1: 数据采集 =====
    logger.info("\n📡 PHASE 1: Data Collection")
    logger.info("-" * 40)
    
    all_entries: List[IPEntry] = []
    source_stats: Dict[str, int] = {}
    
    for source in SOURCES:
        try:
            entries = process_source(source)
            all_entries.extend(entries)
            source_stats[source['name']] = len(entries)
        except Exception as e:
            logger.error(f"❌ Error processing {source['name']}: {e}")
            source_stats[source['name']] = 0
    
    logger.info(f"\n📊 Raw total: {len(all_entries)}")
    
    # ===== 阶段 2: 去重排序 =====
    logger.info("\n🔄 PHASE 2: Deduplication")
    logger.info("-" * 40)
    
    unique_entries = deduplicate_entries(all_entries)
    unique_entries = sort_entries(unique_entries)
    
    logger.info(f"📊 Unique entries: {len(unique_entries)}")
    
    # ===== 阶段 3: 验证 =====
    if not SKIP_VALIDATION and unique_entries:
        logger.info("\n🔍 PHASE 3: Validation")
        logger.info("-" * 40)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                validate_entries_async(
                    unique_entries,
                    timeout=VALIDATION_TIMEOUT,
                    concurrency=VALIDATION_CONCURRENCY
                )
            )
        finally:
            loop.close()
        
        valid_count = sum(1 for e in unique_entries if e.is_valid)
        logger.info(f"\n📊 Valid: {valid_count}/{len(unique_entries)}")
    else:
        logger.info("\n⏭️  PHASE 3: Validation SKIPPED")
    
    # ===== 阶段 4: 导出 =====
    logger.info("\n💾 PHASE 4: Export")
    logger.info("-" * 40)
    
    stats = {'sources': source_stats}
    exporter = Exporter(OUTPUT_DIR)
    exporter.export_all(unique_entries, stats)
    
    # ===== 完成 =====
    elapsed = time.time() - start_time
    
    logger.info("\n" + "=" * 60)
    logger.info("✨ COMPLETED")
    logger.info("=" * 60)
    logger.info(f"📊 Total: {len(unique_entries)} entries")
    logger.info(f"⏱️  Time: {elapsed:.1f}s")
    logger.info("=" * 60)
    
    # 输出文件列表
    logger.info("\n📁 Output files:")
    for f in ["all.txt", "all.json", "all.csv", "valid_only.txt", "summary.md"]:
        logger.info(f"   - output/{f}")
    logger.info("   - all.txt (root)")


if __name__ == "__main__":
    main()
