#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain List Custom Rule Engine (面向对象规则引擎)
用于从 geosite publish 目录、远程 Clash 规则、Dnsmasq 配置、GFWList 等多种数据源中提取、
去重（Trie 冗余子域名剔除 & DOMAIN 与 DOMAIN-SUFFIX 互斥去重），生成规范的 Mihomo rule-set 分流列表。
"""

import argparse
import hashlib
import os
import re
import sys
import urllib.request
from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

DEFAULT_ENV: Dict[str, str] = {
    "fakeip_filter": "https://raw.githubusercontent.com/DustinWin/ShellCrash/dev/public/fake_ip_filter.list",
    "private": "https://magicrule.pages.dev/data/_shared/artifacts/Lan_rules_a7096f98ad43c9dc.list",
    "ads": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml",
    "trackerslist1": "https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/all.txt",
    "trackerslist2": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "applications1": "https://magicrule.pages.dev/data/_shared/artifacts/Download_rules_45c9b3c4889075b6.list",
    "applications2": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt",
    "apple_cn": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf",
    "google_cn": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf",
    "games_cn1": "https://magicrule.pages.dev/data/_shared/artifacts/SteamCN_rules_f86755549ad8ec69.list",
    "games_cn2": "https://magicrule.pages.dev/data/_shared/artifacts/ChinaGame_rules_f2b2794467b8111e.list",
    "netflix": "https://magicrule.pages.dev/data/_shared/artifacts/Netflix_rules_56d52a775e1c2240.list",
    "disney": "https://magicrule.pages.dev/data/_shared/artifacts/Disney_rules_2b565301c4989fb0.list",
    "max": "https://magicrule.pages.dev/data/_shared/artifacts/HBO_rules_969e49342837689c.list",
    "primevideo": "https://magicrule.pages.dev/data/_shared/artifacts/PrimeVideo_rules_79865b76ba7e24aa.list",
    "appletv": "https://magicrule.pages.dev/data/_shared/artifacts/AppleTV_rules_f9dcb0d2f34bf797.list",
    "youtube": "https://magicrule.pages.dev/data/_shared/artifacts/YouTube_rules_329ca26de78c21fe.list",
    "tiktok": "https://magicrule.pages.dev/data/_shared/artifacts/TikTok_rules_f1418ba5f368c034.list",
    "bilibili": "https://magicrule.pages.dev/data/_shared/artifacts/BiliBili_rules_2465ea6448cc4fe0.list",
    "spotify": "https://magicrule.pages.dev/data/_shared/artifacts/Spotify_rules_f68f1309f01d1ad3.list",
    "media": "https://magicrule.pages.dev/data/_shared/artifacts/GlobalMedia_rules_cbbbcb6dca56af83.list",
    "games1": "https://magicrule.pages.dev/data/_shared/artifacts/GlobalGame_rules_d8c6da812d5e7f0b.list",
    "games2": "https://magicrule.pages.dev/data/_shared/artifacts/GameDownload_rules_99528f2898a794ff.list",
    "ai": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list",
    "ai1": "https://magicrule.pages.dev/data/_shared/artifacts/Gemini_rules_8da136e527c6fa11.list",
    "ai2": "https://magicrule.pages.dev/data/_shared/artifacts/Copilot_rules_a253cdc8a666e0cb.list",
    "ai3": "https://magicrule.pages.dev/data/_shared/artifacts/OpenAI_rules_f362ba1006ae0e0c.list",
    "ai4": "https://magicrule.pages.dev/data/_shared/artifacts/Grok_rules_1686b96ebfe522d0.list",
    "ai5": "https://raw.githubusercontent.com/dler-io/Rules/refs/heads/main/Clash/Provider/AI%20Suite.yaml",
    "ai6": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ai-chat-!cn.list",
    "ai7": "https://raw.githubusercontent.com/shangrenxi/Rules/refs/heads/master/rules/AI.list",
    "networktest": "https://magicrule.pages.dev/data/_shared/artifacts/Speedtest_rules_6431e293aaca07be.list",
    "proxy": "https://magicrule.pages.dev/data/_shared/artifacts/Global_rules_b5f3bb33d8a4698a.list",
    "proxylite1": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ProxyGFWlist.list",
    "proxylite2": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ProxyMedia.list",
    "proxylite3": "https://raw.githubusercontent.com/Na5h1ra/ru1es/refs/heads/main/Clash/Ruleset/Outside.list",
    "proxylite4": "https://raw.githubusercontent.com/Na5h1ra/ru1es/refs/heads/main/Clash/Ruleset/OutsideMedia.list",
    "proxylite5": "https://raw.githubusercontent.com/Na5h1ra/ru1es/refs/heads/main/Clash/Ruleset/P0rn.list",
    "cn1": "https://magicrule.pages.dev/data/_shared/artifacts/China_rules_25adbc0394103807.list",
    "cn2": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
}


# ==============================================================================
# 1. 运行上下文与网络/文件抓取缓存系统
# ==============================================================================

class BuildContext:
    """构建上下文，管理路径、环境变量、规则抽取缓存与网络缓存"""
    def __init__(self,
                 publish_dir: str = "./publish",
                 domains_dir: str = "./domains",
                 tmp_dir: str = "./tmp",
                 cache_dir: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None):
        self.publish_dir = publish_dir
        self.domains_dir = domains_dir
        self.tmp_dir = tmp_dir
        self.cache_dir = cache_dir or os.path.join(tmp_dir, "cache")
        self.env = env or dict(os.environ)
        self.rule_cache: Dict[str, Tuple[Set[str], Set[str]]] = {}
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.domains_dir, exist_ok=True)
        os.makedirs(self.tmp_dir, exist_ok=True)

    def get_env(self, key: str, default: str = "") -> str:
        """从系统环境变量或内置默认值中提取"""
        return self.env.get(key) or os.environ.get(key) or DEFAULT_ENV.get(key, default)


def resolve_source(source: str, context: BuildContext) -> str:
    """解析 source，支持 ${var}、var 或直接 URL / 本地文件路径"""
    if not source:
        return ""
    if source.startswith("${") and source.endswith("}"):
        var_name = source[2:-1]
        return context.get_env(var_name, "")
    if source.startswith("$"):
        var_name = source[1:]
        return context.get_env(var_name, "")
    if source in DEFAULT_ENV or source in context.env:
        return context.get_env(source, "")
    return source


def fetch_content(source: str, context: BuildContext) -> str:
    """获取 source 内容，优先读缓存与本地文件，支持 HTTP(S) 下载与重试"""
    resolved = resolve_source(source, context)
    if not resolved:
        return ""

    # 本地文件路径检测
    for candidate in [resolved,
                      os.path.join(context.publish_dir, resolved),
                      os.path.join(context.tmp_dir, resolved),
                      os.path.join(".", resolved)]:
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except Exception as e:
                print(f"[WARN] Failed to read file {candidate}: {e}", file=sys.stderr)
                return ""

    # 网络 URL 下载与缓存
    if resolved.startswith("http://") or resolved.startswith("https://"):
        url_hash = hashlib.md5(resolved.encode("utf-8")).hexdigest()
        cache_file = os.path.join(context.cache_dir, f"{url_hash}.txt")
        if os.path.isfile(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except Exception:
                pass

        req = urllib.request.Request(
            resolved,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    text = resp.read().decode("utf-8", errors="ignore")
                    with open(cache_file, "w", encoding="utf-8") as f:
                        f.write(text)
                    return text
            except Exception as e:
                if attempt == 2:
                    print(f"[WARN] Failed to download {resolved} after 3 attempts: {e}", file=sys.stderr)
                continue

    return ""


# ==============================================================================
# 2. 冗余算法：Trie 树子域名去重 & DOMAIN vs DOMAIN-SUFFIX 互斥过滤
# ==============================================================================

def eliminate_redundant_suffixes(suffixes: Iterable[str]) -> Set[str]:
    """
    匹配原 findRedundantDomain.py 的 Trie 树算法：
    去除 DOMAIN-SUFFIX 类型中冗余的子域名。
    例如有 foo.com 时，bar.foo.com 会被剔除。
    """
    cleaned: Set[str] = set()
    for s in suffixes:
        s = s.strip().lower().strip(".")
        if s:
            cleaned.add(s)

    # 按照 label 数量升序排序（层级最浅的根域先插入）
    domain_list = sorted(cleaned, key=lambda d: len(d.split(".")))
    tree: Dict = {}
    LEAF = 1
    kept_suffixes: Set[str] = set()

    for domain in domain_list:
        labels = domain.split(".")
        node = tree
        redundant = False
        while len(labels) > 0:
            label = labels.pop()
            if label in node:
                if node[label] == LEAF:
                    redundant = True
                    break
            else:
                if len(labels) == 0:
                    node[label] = LEAF
                else:
                    node[label] = {}
            node = node[label]

        if not redundant:
            kept_suffixes.add(domain)

    return kept_suffixes


def filter_domain_against_suffixes(others: Iterable[str], suffixes: Set[str]) -> Set[str]:
    """
    过滤算法：
    仅保留且支持以下前缀规则：
    1. DOMAIN（精准匹配：若自身或任何一级父域名已在 suffix_set 中，则判定冗余剔除）
    2. DOMAIN-KEYWORD（关键字匹配）
    3. DOMAIN-REGEX / REGEX（正则表达式匹配）
    其它非域名类型（如 PROCESS-NAME、IP-CIDR 等）一律过滤去除。
    """
    ALLOWED_PREFIXES = {"DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "REGEX"}
    kept_others: Set[str] = set()

    for line in others:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        prefix = parts[0].strip().upper()
        if prefix not in ALLOWED_PREFIXES:
            continue

        val = parts[1].strip()
        if prefix == "DOMAIN":
            domain = val.lower()
            arr = domain.split(".")
            n = len(arr)
            found = False
            for j in range(n):
                parent = ".".join(arr[j:])
                if parent in suffixes:
                    found = True
                    break
            if not found:
                kept_others.add(f"DOMAIN,{domain}")
        else:
            kept_others.add(f"{prefix},{val}")

    return kept_others


# ==============================================================================
# 3. 面向对象过滤规则类体系 (Filter Subclasses)
# ==============================================================================

class BaseFilter(ABC):
    """过滤规则抽象基类"""
    @abstractmethod
    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        """
        提取规则
        :return: (suffixes, others)
                 suffixes: 纯域名后缀集合（无需 DOMAIN-SUFFIX, 前缀）
                 others: 包含规则类型前缀的行集合（如 DOMAIN,xxx, DOMAIN-KEYWORD,kw 等）
        """
        pass


class CommunityFilter(BaseFilter):
    """
    解析 geosite 生成的 ./publish/<filename> 文件
    提取 domain:xxx[:@tag] -> suffix
    提取 full:xxx[:@tag]   -> DOMAIN,xxx
    提取 keyword:xxx[:@tag]-> DOMAIN-KEYWORD,xxx
    """
    def __init__(self, filename: str, tag: Optional[str] = None,
                 allow_untagged: Optional[bool] = None,
                 extract_suffix: bool = True,
                 extract_full: bool = True,
                 extract_keyword: bool = True):
        self.filename = filename
        self.tag = tag.lstrip("@") if tag else None
        # 如果指定了 tag="cn"，默认不允许无 tag 匹配；若 tag="!cn" 或 None，默认允许
        if allow_untagged is None:
            self.allow_untagged = False if (self.tag == "cn") else True
        else:
            self.allow_untagged = allow_untagged
        self.extract_suffix = extract_suffix
        self.extract_full = extract_full
        self.extract_keyword = extract_keyword

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()
        content = fetch_content(self.filename, context)
        if not content:
            print(f"[INFO] '{self.filename}' 未在 '{context.publish_dir}' 中找到（在 CI 中该文件由 Go 编译 geosite 自动生成）", file=sys.stderr)
            return suffixes, others

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            rule_type = parts[0].strip().lower()
            val = parts[1].strip()
            tags = set()
            for p in parts[2:]:
                for item in p.split(","):
                    t = item.strip().lstrip("@")
                    if t:
                        tags.add(t)

            # 标签过滤
            if self.tag is not None:
                if not tags:
                    if not self.allow_untagged:
                        continue
                else:
                    if self.tag not in tags:
                        continue

            if rule_type == "domain" and self.extract_suffix:
                suffixes.add(val.lower())
            elif rule_type == "full" and self.extract_full:
                others.add(f"DOMAIN,{val.lower()}")
            elif rule_type == "keyword" and self.extract_keyword:
                others.add(f"DOMAIN-KEYWORD,{val.lower()}")

        return suffixes, others


class ClashFilter(BaseFilter):
    """
    解析 Clash classical 规则文件（URL 或本地路径）
    提取 DOMAIN-SUFFIX,domain -> suffix
    提取 DOMAIN, DOMAIN-KEYWORD, DOMAIN-REGEX, REGEX -> others
    严格忽略 PROCESS-NAME、IP-CIDR 等非目标类型
    """
    def __init__(self, sources: Union[str, List[str]],
                 extract_suffix: bool = True,
                 extract_other: bool = True):
        self.sources = [sources] if isinstance(sources, str) else list(sources)
        self.extract_suffix = extract_suffix
        self.extract_other = extract_other
        self.allowed_types = ("DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "REGEX")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()

        for src in self.sources:
            content = fetch_content(src, context)
            if not content:
                continue
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("- "):
                    line = line[2:].strip()
                parts = [p.strip() for p in line.split(",") if p.strip()]
                if not parts:
                    continue
                rule_type = parts[0].upper()
                if rule_type == "DOMAIN-SUFFIX" and self.extract_suffix and len(parts) >= 2:
                    suffixes.add(parts[1].lower())
                elif rule_type in self.allowed_types and self.extract_other and len(parts) >= 2:
                    others.add(f"{rule_type},{parts[1]}")

        return suffixes, others


class ClashYamlFilter(BaseFilter):
    """
    解析 Clash Provider YAML 列表（如 AI Suite.yaml 或 applications2 列表）
    提取 - DOMAIN-SUFFIX,domain -> suffix
    提取 - DOMAIN,xxx / - DOMAIN-KEYWORD,xxx / - REGEX,xxx -> others
    """
    def __init__(self, source: str):
        self.source = source
        self.allowed_types = ("DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "REGEX")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()

        content = fetch_content(self.source, context)
        if not content:
            return suffixes, others

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("- "):
                line = line[2:].strip()
            line = line.strip("'\"")
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if not parts:
                continue
            rule_type = parts[0].upper()
            if rule_type == "DOMAIN-SUFFIX" and len(parts) >= 2:
                suffixes.add(parts[1].lower())
            elif rule_type in self.allowed_types and len(parts) >= 2:
                others.add(f"{rule_type},{parts[1]}")

        return suffixes, others


class DnsmasqFilter(BaseFilter):
    """
    解析 server=/domain/ip 格式文件
    若 as_suffix 为 True，提取为 suffix (如 cn2 accelerated-domains)
    若 as_suffix 为 False，提取为 DOMAIN,domain (如 apple_cn, google_cn)
    """
    def __init__(self, source: str, as_suffix: bool = False):
        self.source = source
        self.as_suffix = as_suffix
        self.pattern = re.compile(r"server=\/([^\/]+)")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()
        content = fetch_content(self.source, context)
        if not content:
            return suffixes, others

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = self.pattern.search(line)
            if m:
                domain = m.group(1).strip().lower()
                if self.as_suffix:
                    suffixes.add(domain)
                else:
                    others.add(f"DOMAIN,{domain}")

        return suffixes, others


class AntiAdFilter(BaseFilter):
    """
    解析 anti-ad clash yaml 或 meta-rules-dat 格式
    '+.domain' 或以 '+.' 开头 -> suffix
    'domain' 或无前缀普通域名 -> DOMAIN,domain
    """
    def __init__(self, source: str):
        self.source = source
        self.quoted_pattern = re.compile(r"'([^']+)'")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()
        content = fetch_content(self.source, context)
        if not content:
            return suffixes, others

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line == "payload:":
                continue

            m = self.quoted_pattern.search(line)
            if m:
                entry = m.group(1).strip()
            else:
                if line.startswith("- "):
                    line = line[2:].strip()
                entry = line.strip("'\"")

            if not entry or entry.startswith("#"):
                continue

            if entry.startswith("+.") or entry.startswith("*."):
                domain = entry[2:].strip().lower()
                if domain:
                    suffixes.add(domain)
            elif entry.lower().startswith("domain-suffix,"):
                suffixes.add(entry.split(",", 1)[1].strip().lower())
            elif entry.lower().startswith("domain,"):
                others.add(f"DOMAIN,{entry.split(',', 1)[1].strip().lower()}")
            else:
                domain = entry.lower()
                others.add(f"DOMAIN,{domain}")

        return suffixes, others


class TrackersFilter(BaseFilter):
    """
    解析 trackers 列表：提取 hostname:port -> DOMAIN,hostname
    """
    def __init__(self, sources: Union[str, List[str]]):
        self.sources = [sources] if isinstance(sources, str) else list(sources)
        self.tld_pattern = re.compile(r"\.[a-zA-Z]")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        others: Set[str] = set()

        for src in self.sources:
            content = fetch_content(src, context)
            if not content:
                continue
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not self.tld_pattern.search(line):
                    continue

                if "://" in line:
                    parts = re.split(r"[/:]+", line)
                    host = parts[1] if len(parts) > 1 else ""
                else:
                    parts = re.split(r"[/:]+", line)
                    host = parts[0] if len(parts) > 0 else ""

                host = host.strip().lower()
                if host and "." in host and not host.replace(".", "").isdigit():
                    others.add(f"DOMAIN,{host}")

        return set(), others


class FakeIpFilter(BaseFilter):
    """
    解析 fake_ip_filter 列表：
    - `+.domain` 或 `*.domain` -> suffix
    - 无特殊符号域名 -> DOMAIN,domain
    - 正则通配符规则 -> DOMAIN-REGEX,^...$
    - lite=True 仅匹配 ntp|stun|time
    """
    def __init__(self, source: str, lite: bool = False):
        self.source = source
        self.lite = lite

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()
        content = fetch_content(self.source, context)
        if not content:
            return suffixes, others

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if self.lite:
                if not re.search(r"ntp|stun|time", line, re.IGNORECASE):
                    continue

            # 1. ^[+*]\.([^*]+)$ -> suffix
            m = re.match(r"^[\+\*]\.([^\*]+)$", line)
            if m:
                suffixes.add(m.group(1).strip().lower())
                continue

            # 2. 纯域名：!/[#+* ]/ -> DOMAIN,
            if not re.search(r"[#+* ]", line):
                others.add(f"DOMAIN,{line.strip().lower()}")
                continue

            # 3. 包含 * 且无 . -> DOMAIN-REGEX
            if "*" in line and "#" not in line and "." not in line:
                transformed = line.replace("*", r"[^\.]+")
                others.add(f"DOMAIN-REGEX,^{transformed}$")
                continue

            # 4. 包含 .* 或空格
            if "#" not in line and (".*" in line or " " in line):
                transformed = line.replace(" ", r"\s").replace(".", r"\.").replace("*", r"[^\.]+")
                if transformed.startswith("+"):
                    transformed = ".*" + transformed[1:]
                others.add(f"DOMAIN-REGEX,^{transformed}$")

        return suffixes, others


class StaticFilter(BaseFilter):
    """直接注入静态指定的域名列表"""
    def __init__(self, suffixes: Optional[List[str]] = None, others: Optional[List[str]] = None):
        self.suffixes = set(s.strip().lower() for s in (suffixes or []))
        self.others = set(others or [])

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        return set(self.suffixes), set(self.others)


class GfwFilter(BaseFilter):
    """解析 temp-gfw.txt（gfwlist 转换结果）为标准域名并作为 suffix 输出"""
    def __init__(self, source_file: str):
        self.source_file = source_file
        self.pattern = re.compile(r"^((?=^.{3,255})[a-zA-Z0-9][-_a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-_a-zA-Z0-9]{0,62})+)")

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        content = fetch_content(self.source_file, context)
        if not content:
            return suffixes, set()

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = self.pattern.match(line)
            if m:
                suffixes.add(m.group(1).strip().lower())

        return suffixes, set()


# ==============================================================================
# 4. 分流规则对象 (RoutingRule) 与规则注册表 (RuleRegistry)
# ==============================================================================

class RoutingRule:
    """分流规则对象，组合多个 Filter，支持排除规则 (exclude) 与自动构建去重"""
    def __init__(self, name: str, deduplicate: bool = True):
        self.name = name
        self.deduplicate = deduplicate
        self.filters: List[BaseFilter] = []
        self.exclusions: List[Union["RoutingRule", str]] = []

    def add_filter(self, filter_obj: BaseFilter) -> "RoutingRule":
        self.filters.append(filter_obj)
        return self

    def exclude(self, other_rule_or_name: Union["RoutingRule", str]) -> "RoutingRule":
        self.exclusions.append(other_rule_or_name)
        return self

    def extract(self, context: BuildContext) -> Tuple[Set[str], Set[str]]:
        suffixes: Set[str] = set()
        others: Set[str] = set()
        for f in self.filters:
            s, o = f.extract(context)
            suffixes.update(s)
            others.update(o)
        return suffixes, others

    def build(self, context: BuildContext, registry: Optional["RuleRegistry"] = None) -> List[str]:
        # 1. 抽取当前规则数据
        if self.name in context.rule_cache:
            raw_suffixes, raw_others = context.rule_cache[self.name]
        else:
            raw_suffixes, raw_others = self.extract(context)
            context.rule_cache[self.name] = (set(raw_suffixes), set(raw_others))

        suffixes = set(raw_suffixes)
        others = set(raw_others)

        # 2. 处理排除规则（如 games 排除 games-cn）
        for exc in self.exclusions:
            exc_rule: Optional[RoutingRule] = None
            if isinstance(exc, RoutingRule):
                exc_rule = exc
            elif registry and isinstance(exc, str):
                exc_rule = registry.get(exc)

            if exc_rule:
                if exc_rule.name in context.rule_cache:
                    exc_suffixes, exc_others = context.rule_cache[exc_rule.name]
                else:
                    exc_suffixes, exc_others = exc_rule.extract(context)
                    context.rule_cache[exc_rule.name] = (set(exc_suffixes), set(exc_others))
                suffixes -= exc_suffixes
                others -= exc_others

        # 3. 冗余子域名消除 & DOMAIN 互斥过滤
        if self.deduplicate:
            cleaned_suffixes = eliminate_redundant_suffixes(suffixes)
            cleaned_others = filter_domain_against_suffixes(others, cleaned_suffixes)
        else:
            cleaned_suffixes = suffixes
            cleaned_others = others

        # 4. 组装格式化行并去重排序
        # 注意：DOMAIN-KEYWORD 不被 mihomo mrs domain behavior 支持，统一丢弃
        output_lines: List[str] = [f"DOMAIN-SUFFIX,{s}" for s in cleaned_suffixes]
        output_lines.extend(line for line in cleaned_others if not line.upper().startswith("DOMAIN-KEYWORD,"))

        unique_lines = list(set(output_lines))
        unique_lines.sort(key=lambda x: x.lower())

        # 5. 写入 ./domains/<name>.list
        out_path = os.path.join(context.domains_dir, f"{self.name}.list")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            for line in unique_lines:
                f.write(line + "\n")

        print(f"[{self.name}] Built {len(unique_lines)} rules -> {out_path}")
        return unique_lines


class RuleRegistry:
    """分流规则注册中心与工厂管理器"""
    def __init__(self):
        self.rules: Dict[str, RoutingRule] = {}
        self.order: List[str] = []

    def register(self, rule: RoutingRule) -> RoutingRule:
        self.rules[rule.name] = rule
        if rule.name not in self.order:
            self.order.append(rule.name)
        return rule

    def get(self, name: str) -> Optional[RoutingRule]:
        return self.rules.get(name)

    def list_rules(self) -> List[str]:
        return list(self.order)

    def build_all(self, context: BuildContext) -> None:
        for name in self.order:
            self.rules[name].build(context, registry=self)

    def build_one(self, name: str, context: BuildContext) -> bool:
        rule = self.get(name)
        if not rule:
            print(f"[ERROR] Rule '{name}' not found in registry!", file=sys.stderr)
            return False
        rule.build(context, registry=self)
        return True


# ==============================================================================
# 5. 规则注册工厂（覆盖 build.yml 中全部 29 个分流规则）
# ==============================================================================

def create_media_rule(name: str, community_file: str, env_var: str) -> RoutingRule:
    """通用媒体分流规则构建函数"""
    return (RoutingRule(name)
            .add_filter(CommunityFilter(community_file))
            .add_filter(ClashFilter(env_var)))


def get_default_registry() -> RuleRegistry:
    reg = RuleRegistry()

    # 1. fakeip-filter
    reg.register(
        RoutingRule("fakeip-filter")
        .add_filter(FakeIpFilter("fakeip_filter", lite=False))
    )

    # 2. fakeip-filter-lite
    reg.register(
        RoutingRule("fakeip-filter-lite")
        .add_filter(StaticFilter(others=[
            "DOMAIN,adguardteam.github.io",
            "DOMAIN,adrules.top",
            "DOMAIN,anti-ad.net",
            "DOMAIN,local.adguard.org",
            "DOMAIN,static.adtidy.org",
        ]))
        .add_filter(FakeIpFilter("fakeip_filter", lite=True))
    )

    # 3. private
    reg.register(
        RoutingRule("private")
        .add_filter(CommunityFilter("private.txt"))
        .add_filter(ClashFilter("private"))
        .add_filter(StaticFilter(others=[
            "DOMAIN,board.zash.run.place",
            "DOMAIN,metacubex.github.io",
            "DOMAIN,metacubexd.pages.dev",
            "DOMAIN,yacd.haishan.me",
            "DOMAIN,yacd.metacubex.one",
            "DOMAIN-REGEX,^[^.]+$",
        ]))
    )

    # 4. ads
    reg.register(
        RoutingRule("ads")
        .add_filter(AntiAdFilter("ads"))
    )

    # 5. trackerslist
    reg.register(
        RoutingRule("trackerslist")
        .add_filter(TrackersFilter(["trackerslist1", "trackerslist2"]))
    )

    # 6. applications
    reg.register(
        RoutingRule("applications")
        .add_filter(ClashFilter("applications1"))
        .add_filter(ClashYamlFilter("applications2"))
    )

    # 7. microsoft-cn
    reg.register(
        RoutingRule("microsoft-cn")
        .add_filter(CommunityFilter("microsoft.txt", tag="cn"))
    )

    # 8. apple-cn
    reg.register(
        RoutingRule("apple-cn")
        .add_filter(CommunityFilter("apple.txt", tag="cn"))
        .add_filter(DnsmasqFilter("apple_cn", as_suffix=True))
    )

    # 9. google-cn
    reg.register(
        RoutingRule("google-cn")
        .add_filter(CommunityFilter("google.txt", tag="cn"))
        .add_filter(DnsmasqFilter("google_cn", as_suffix=True))
    )

    # 10. games-cn
    reg.register(
        RoutingRule("games-cn")
        .add_filter(CommunityFilter("category-game-accelerator-cn.txt"))
        .add_filter(CommunityFilter("category-game-platforms-download.txt", tag="cn"))
        .add_filter(CommunityFilter("category-games-cn.txt"))
        .add_filter(ClashFilter(["games_cn1", "games_cn2"]))
    )

    # 10.1 steam-cn（Steam 中国区 CDN/下载，取自 v2fly steam 的 @cn 属性）
    reg.register(
        RoutingRule("steam-cn")
        .add_filter(CommunityFilter("steam.txt", tag="cn"))
    )

    # 10.2 steam（Steam 商店/社区/海外 CDN，全量；配合 steam-cn 先匹配）
    reg.register(
        RoutingRule("steam")
        .add_filter(CommunityFilter("steam.txt"))
    )

    # 11. games (剔除 games-cn)
    reg.register(
        RoutingRule("games")
        .add_filter(CommunityFilter("category-game-platforms-download.txt", tag="!cn"))
        .add_filter(CommunityFilter("category-games-!cn.txt", tag="!cn"))
        .add_filter(ClashFilter(["games1", "games2"]))
        .exclude("games-cn")
    )

    # 12-20. 标准流媒体规则
    reg.register(create_media_rule("netflix", "netflix.txt", "netflix"))
    reg.register(create_media_rule("disney", "disney.txt", "disney"))
    reg.register(create_media_rule("max", "hbo.txt", "max"))
    reg.register(create_media_rule("primevideo", "primevideo.txt", "primevideo"))
    reg.register(create_media_rule("appletv", "apple-tvplus.txt", "appletv"))
    reg.register(create_media_rule("youtube", "youtube.txt", "youtube"))
    reg.register(create_media_rule("tiktok", "tiktok.txt", "tiktok"))
    reg.register(create_media_rule("bilibili", "bilibili.txt", "bilibili"))
    reg.register(create_media_rule("spotify", "spotify.txt", "spotify"))

    # 21. media
    reg.register(
        RoutingRule("media")
        .add_filter(ClashFilter("media"))
    )

    # 22. ai
    reg.register(
        RoutingRule("ai")
        .add_filter(CommunityFilter("category-ai-!cn.txt"))
        .add_filter(ClashFilter(["ai", "ai1", "ai2", "ai3", "ai4", "ai7"]))
        .add_filter(ClashYamlFilter("ai5"))
        .add_filter(AntiAdFilter("ai6"))
    )

    # 23. networktest
    reg.register(
        RoutingRule("networktest")
        .add_filter(CommunityFilter("category-speedtest.txt", extract_suffix=True, extract_full=True, extract_keyword=True))
        .add_filter(ClashFilter("networktest"))
        .add_filter(StaticFilter(others=[
            "DOMAIN-KEYWORD,ipv6-test",
            "DOMAIN-KEYWORD,ipv6test",
            "DOMAIN-KEYWORD,test-ipv6",
            "DOMAIN-KEYWORD,testipv6",
        ]))
    )

    # 24. tld-proxy
    reg.register(
        RoutingRule("tld-proxy")
        .add_filter(CommunityFilter("tld-!cn.txt"))
    )

    # 25. proxy
    reg.register(
        RoutingRule("proxy")
        .add_filter(GfwFilter("./tmp/temp-gfw.txt"))
        .add_filter(CommunityFilter("geolocation-!cn.txt"))
        .add_filter(ClashFilter("proxy"))
    )

    # 26. gfw
    reg.register(
        RoutingRule("gfw")
        .add_filter(GfwFilter("./tmp/temp-gfw.txt"))
    )

    # 27. proxylite
    reg.register(
        RoutingRule("proxylite")
        .add_filter(ClashFilter(["proxylite1", "proxylite2", "proxylite3", "proxylite4", "proxylite5"]))
    )

    # 28. cn
    reg.register(
        RoutingRule("cn")
        .add_filter(CommunityFilter("cn.txt"))
        .add_filter(ClashFilter("cn1"))
        .add_filter(DnsmasqFilter("cn2", as_suffix=True))
    )

    # 29. cn-lite
    reg.register(
        RoutingRule("cn-lite")
        .add_filter(CommunityFilter("cn.txt"))
        .add_filter(ClashFilter("cn1"))
    )

    return reg


# ==============================================================================
# 6. CLI 命令行入口
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Object-Oriented Domain Routing Rule Generator")
    parser.add_argument("--rule", type=str, help="Build specific rule by name (e.g. netflix)")
    parser.add_argument("--list", action="store_true", help="List all registered rules")
    parser.add_argument("--publish-dir", type=str, default="./publish", help="Path to geosite publish directory")
    parser.add_argument("--domains-dir", type=str, default="./domains", help="Path to output domains directory")
    parser.add_argument("--tmp-dir", type=str, default="./tmp", help="Path to temporary cache directory")

    args = parser.parse_args()
    registry = get_default_registry()

    if args.list:
        print("Registered Routing Rules:")
        for idx, rname in enumerate(registry.list_rules(), 1):
            print(f"  {idx:2d}. {rname}")
        return

    context = BuildContext(
        publish_dir=args.publish_dir,
        domains_dir=args.domains_dir,
        tmp_dir=args.tmp_dir
    )

    if args.rule:
        success = registry.build_one(args.rule, context)
        sys.exit(0 if success else 1)
    else:
        print(f"Starting domain rules generation for all {len(registry.list_rules())} rules...")
        registry.build_all(context)
        print("All domain rules generated successfully!")


if __name__ == "__main__":
    main()
