#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ThreatLink - 威胁情报检测工具
用于检测网站外链劫持漏洞，识别过期域名、恶意重定向等威胁
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
import ipaddress

import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
from fake_useragent import UserAgent
from colorama import init, Fore, Style
from tqdm import tqdm

# 初始化colorama
init(autoreset=True)

def show_banner():
    """显示启动横幅"""
    banner = f"""
{Fore.CYAN}/$$$$$$$$ /$$                                       /$$     /$$       /$$           /$$      
{Fore.CYAN}|__  $$__/| $$                                      | $$    | $$      |__/          | $$      
{Fore.CYAN}   | $$   | $$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$  | $$       /$$ /$$$$$$$ | $$   /$$
{Fore.CYAN}   | $$   | $$__  $$ /$$__  $$ /$$__  $$ |____  $$|_  $$_/  | $$      | $$| $$__  $$| $$  /$$/
{Fore.CYAN}   | $$   | $$  \ $$| $$  \__/| $$$$$$$$  /$$$$$$$  | $$    | $$      | $$| $$  \ $$| $$$$$$/ 
{Fore.CYAN}   | $$   | $$  | $$| $$      | $$_____/ /$$__  $$  | $$ /$$| $$      | $$| $$  | $$| $$_  $$ 
{Fore.CYAN}   | $$   | $$  | $$| $$      |  $$$$$$$|  $$$$$$$  |  $$$$/| $$$$$$$$| $$| $$  | $$| $$ \  $$
{Fore.CYAN}   |__/   |__/  |__/|__/       \_______/ \_______/   \___/  |________/|__/|__/  |__/|__/  \__/
{Fore.CYAN}                                                                                              
{Fore.CYAN}                                                                                              
{Fore.CYAN}                                                                                              
{Fore.CYAN}  ______
{Fore.CYAN} /      \                                  
{Fore.CYAN}|  $$$$$$\  _______  ______   _______      
{Fore.CYAN}| $$___\$$ /       \|      \ |       \     
{Fore.CYAN} \$$    \ |  $$$$$$$ \$$$$$$\| $$$$$$$\    
{Fore.CYAN} _\$$$$$$\| $$      /      $$| $$  | $$    
{Fore.CYAN}|  \__| $$| $$_____|  $$$$$$$| $$  | $$    
{Fore.CYAN} \$$    $$ \$$     \\$$    $$| $$  | $$    
{Fore.CYAN}  \$$$$$$   \$$$$$$$ \$$$$$$$ \$$   \$$    
{Fore.CYAN}                                                                      
{Style.RESET_ALL}"""
    print(banner)
    
    # 添加作者信息和工具介绍
    info_text = f"""
{Fore.YELLOW}ThreatLink - 威胁情报检测工具
{Fore.YELLOW}[+] by Att@ckxu
{Style.RESET_ALL}"""
    print(info_text)
    time.sleep(0.5)  # 短暂停顿让用户看到横幅

@dataclass
class ThreatResult:
    """威胁检测结果"""
    url: str
    domain: str
    link_title: str  # 外链标题（来自标签title或文本）
    threat_level: str  # low, medium, high, critical
    threat_type: str
    description: str
    evidence: str
    recommendation: str
    timestamp: str
    source_url: str  # 威胁来源的原始URL

@dataclass
class LinkInfo:
    """链接信息"""
    url: str
    domain: str
    title: str
    text: str
    position: str  # footer, header, content, sidebar
    is_external: bool

class ThreatIntelligenceScanner:
    """威胁情报扫描器"""
    
    def __init__(self, config: Dict = None):
        # 合并默认配置 + 配置文件 + 外部传入配置，确保排除/白名单等默认项不丢失
        defaults = self._default_config()
        file_cfg = self._load_external_config()
        merged = {**defaults, **file_cfg}
        if config:
            for k, v in config.items():
                if v is not None:
                    merged[k] = v
        self.config = merged
        self.session = requests.Session()
        self.ua = UserAgent()
        self.results: List[ThreatResult] = []
        
        # 设置请求头
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # 设置日志
        self._setup_logging()
        
        # 恶意关键词 - 增强版
        self.malicious_keywords = {
            'gambling': [
                # 博彩相关
                'casino', 'poker', 'bet', 'gamble', 'lottery', 'slot', 'bingo', 'roulette',
                'blackjack', 'sportsbook', 'betting', 'odds', 'jackpot', 'win', 'prize',
                '博彩', '赌博', '赌场', '彩票', '投注', '下注', '赔率', '中奖',
                '澳门', '拉斯维加斯', '老虎机', '百家乐', '轮盘', '21点',
                # 体育博彩
                'sports betting', 'football bet', 'basketball bet', 'soccer bet',
                '体育博彩', '足球投注', '篮球投注', '竞彩', '体彩'
            ],
            'porn': [
                # 色情相关
                'porn', 'adult', 'sex', 'xxx', 'nude', 'naked', 'pornography', 'erotic',
                'escort', 'massage', 'dating', 'hookup', 'fetish', 'bdsm',
                '色情', '成人', '性', '裸体', '情色', '按摩', '约会', '交友',
                '援交', '包夜', '上门', '特殊服务'
            ],
            'pirate': [
                # 盗版影视
                'torrent', 'download', 'free movie', 'streaming', 'pirate', 'crack',
                'movie download', 'tv show', 'anime', 'drama', 'film', 'cinema',
                '盗版', '下载', '免费电影', '在线观看', '影视', '电影', '电视剧',
                '动漫', '韩剧', '美剧', '日剧', '综艺', '纪录片'
            ],
            'sports': [
                # 体育博彩
                'sports', 'football', 'basketball', 'soccer', 'tennis', 'baseball',
                'hockey', 'golf', 'boxing', 'mma', 'ufc', 'racing', 'f1',
                '体育', '足球', '篮球', '网球', '棒球', '冰球', '高尔夫',
                '拳击', '格斗', '赛车', 'f1', '英超', '西甲', '德甲', '意甲'
            ],
            'malware': [
                # 恶意软件
                 'hack', 'cheat', 'exploit',
                 '破解', '补丁', '外挂'
            ]
        }
    
    def _default_config(self) -> Dict:
        """默认配置"""
        return {
            'timeout': 10,
            'max_redirects': 5,
            'threads': 5,
            'delay': 1,
            'user_agents': True,
            'check_dns': True,
            'check_whois': False,  # 默认关闭WHOIS检查
            'check_content': True,
            'autosave': False,  # 是否在每个URL后自动保存部分结果
            'exclude_domains_with_labels': ['edu', 'gov'],  # 排除含有这些标签的域名（广义）
            'exclude_domain_suffixes': ['.edu.cn', '.gov.cn'],  # 精确后缀排除
            'exclude_private_ips': True,  # 排除内网IP
            'exclude_ip_prefixes': ['10.', '192.168.', '172.'],  # 额外前缀快速判断
            'output_format': 'json',
            'output_file': f'threat_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        }
    
    def _setup_logging(self):
        """设置日志"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s',
            handlers=[
                logging.FileHandler('threat_scanner.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_external_config(self) -> Dict:
        """从 config.json 读取外部配置（若存在）"""
        try:
            cfg_path = os.path.join(os.getcwd(), 'config.json')
            if os.path.exists(cfg_path):
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 支持两层结构：直接键或 data["scanner"]
                    scanner_cfg = data.get('scanner', {}) if isinstance(data, dict) else {}
                    # 允许顶层直接放配置键
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if k not in ('scanner', 'threat_detection', 'output'):
                                scanner_cfg[k] = v
                    # 仅返回识别到的键
                    return scanner_cfg
        except Exception as e:
            # 读取失败时忽略，使用默认配置
            pass
        return {}
    
    def _decode_response_text(self, response: requests.Response) -> str:
        """尽量正确解码响应文本，修复中文标题乱码问题"""
        try:
            # 优先使用服务器声明的编码；若为ISO-8859-1或缺失，则使用apparent_encoding
            enc = (response.encoding or '').strip()
            if not enc or enc.lower() == 'iso-8859-1':
                response.encoding = response.apparent_encoding or 'utf-8'
            return response.text
        except Exception:
            try:
                return response.content.decode('utf-8', errors='replace')
            except Exception:
                return response.content.decode(errors='replace')
    
    def scan_url(self, url: str) -> List[ThreatResult]:
        """扫描单个URL"""
        self.logger.info(f"开始扫描: {url}")
        
        try:
            # 1. 获取页面内容
            page_content = self._fetch_page(url)
            if not page_content:
                return []
            
            # 2. 提取外链
            external_links = self._extract_external_links(url, page_content)
            self.logger.info(f"发现 {len(external_links)} 个外链")
            
            # 3. 分析每个外链
            threats = []
            for link in tqdm(external_links, desc="分析外链"):
                threat = self._analyze_link(link, source_url=url)
                if threat:
                    threats.append(threat)
            
            # 4. 去重处理
            unique_threats = self._deduplicate_results(threats)
            return unique_threats
            
        except Exception as e:
            self.logger.error(f"扫描 {url} 时出错: {str(e)}")
            return []
    
    def _fetch_page(self, url: str) -> Optional[str]:
        """获取页面内容"""
        try:
            response = self.session.get(
                url, 
                timeout=self.config['timeout'],
                allow_redirects=True
            )
            response.raise_for_status()
            return self._decode_response_text(response)
        except Exception as e:
            self.logger.error(f"获取页面失败 {url}: {str(e)}")
            return None
    
    def _extract_external_links(self, base_url: str, html_content: str) -> List[LinkInfo]:
        """提取外链"""
        soup = BeautifulSoup(html_content, 'html.parser')
        base_domain = urlparse(base_url).netloc
        external_links = []
        
        # 查找所有链接
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href')
            
            # 转换为绝对URL
            absolute_url = urljoin(base_url, href)
            parsed_url = urlparse(absolute_url)
            
            # 检查是否为外链
            if parsed_url.netloc and parsed_url.netloc.lower() != base_domain.lower():
                hostname = (parsed_url.hostname or '').lower()
                # 排除内网/私有IP与配置前缀
                if self._is_excluded_ip(hostname):
                    continue
                # 排除配置中指定标签（如 edu、gov）的域名，降低误报
                if self._is_excluded_domain(parsed_url.netloc):
                    continue
                # URL 白名单：命中则完全跳过
                if self._is_whitelisted_url(absolute_url):
                    continue
                # 确定链接位置
                position = self._determine_link_position(tag)
                
                # 提取标题时避免乱码：优先a@title，其次文本；都存在时选择更长且可能信息量大的
                title_attr = tag.get('title') or ''
                text_content = tag.get_text(strip=True) or ''
                link_title = title_attr if len(title_attr) >= len(text_content) else text_content

                # 排除学校相关链接（降低误报）
                if self._is_school_related_link(link_title):
                    continue

                link_info = LinkInfo(
                    url=absolute_url,
                    domain=parsed_url.netloc,
                    title=link_title,
                    text=text_content,
                    position=position,
                    is_external=True
                )
                external_links.append(link_info)
        
        return external_links
    
    def _determine_link_position(self, tag) -> str:
        """确定链接在页面中的位置"""
        # 检查父级元素
        parent = tag.parent
        while parent:
            if parent.name in ['footer', 'header', 'nav', 'aside']:
                return parent.name
            if 'footer' in str(parent.get('class', [])).lower():
                return 'footer'
            if 'header' in str(parent.get('class', [])).lower():
                return 'header'
            if 'sidebar' in str(parent.get('class', [])).lower():
                return 'sidebar'
            parent = parent.parent
        
        return 'content'

    def _is_school_related_link(self, link_title: str) -> bool:
        """判断链接标题是否与学校相关（降低误报）"""
        if not link_title:
            return False
        
        school_keywords = [
            '中学', '初中', '高中', '小学', '学校', '学院', '大学', '校区', '分校',
            '教育', '教学', '教师', '学生', '班级', '年级', '课程', '教材', '考试',
            '招生', '录取', '报名', '入学', '毕业', '学位', '学术', '科研', '实验室',
            'middle school', 'high school', 'elementary school', 'college', 'university',
            'education', 'school', 'campus', 'teacher', 'student', 'class', 'grade'
        ]
        
        link_title_lower = link_title.lower()
        for keyword in school_keywords:
            if keyword.lower() in link_title_lower:
                return True
        return False

    def _is_excluded_domain(self, domain: str) -> bool:
        """根据配置判断是否排除此域名。
        规则：
        1) 若以 exclude_domain_suffixes 中任一后缀结尾，则排除（如 .edu.cn, .gov.cn）
        2) 否则，若包含 exclude_domains_with_labels 中任一标签，则排除（较宽松）
        """
        try:
            d = domain.strip().lower()
            dotted = f'.{d}.'
            # 先检查精确后缀
            suffixes = self.config.get('exclude_domain_suffixes', [])
            for suf in suffixes:
                s = str(suf).strip().lower()
                if s and d.endswith(s):
                    return True
            # 再检查宽松标签
            labels = self.config.get('exclude_domains_with_labels', [])
            for label in labels:
                lab = str(label).strip().lower()
                if not lab:
                    continue
                token = f'.{lab}.'
                # 仅当标签作为独立域标签出现时匹配，避免误伤如 'govern'、'education'
                if token in dotted:
                    return True
            return False
        except Exception:
            return False

    def _is_excluded_ip(self, host: str) -> bool:
        """判断主机名是否为需要排除的内网/私有IP"""
        try:
            if not host:
                return False
            # 先按配置的前缀快速判断
            prefixes = self.config.get('exclude_ip_prefixes', []) or []
            for p in prefixes:
                p = str(p).strip().lower()
                if p and host.startswith(p):
                    return True
            # 再用 ipaddress 严格判断
            exclude_private = bool(self.config.get('exclude_private_ips', True))
            # 尝试解析为IP
            try:
                ip_obj = ipaddress.ip_address(host)
                if exclude_private and (ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_loopback):
                    return True
            except ValueError:
                # 不是IP字面量，忽略
                return False
            return False
        except Exception:
            return False
    
    def _is_whitelisted_url(self, url: str) -> bool:
        """是否命中 URL 白名单：命中则完全跳过检测和输出"""
        try:
            whitelist = self.config.get('whitelist_urls', []) or []
            if not whitelist:
                return False
            u = str(url).strip()
            for w in whitelist:
                w = str(w).strip()
                if not w:
                    continue
                if u.startswith(w):
                    return True
            return False
        except Exception:
            return False
    
    def _analyze_link(self, link: LinkInfo, source_url: str) -> Optional[ThreatResult]:
        """分析单个链接的威胁"""
        threats = []
        
        # 1. 检查DNS解析
        dns_threat = self._check_dns_resolution(link, source_url)
        if dns_threat:
            threats.append(dns_threat)
        
        # 2. 检查域名注册信息
        whois_threat = self._check_domain_whois(link, source_url)
        if whois_threat:
            threats.append(whois_threat)
        
        # 3. 检查网站内容
        content_threat = self._check_website_content(link, source_url)
        if content_threat:
            threats.append(content_threat)
        
        # 返回最高威胁等级的结果
        if threats:
            return max(threats, key=lambda x: self._get_threat_level_score(x.threat_level))
        
        return None
    
    def _check_dns_resolution(self, link: LinkInfo, source_url: str) -> Optional[ThreatResult]:
        """检查DNS解析"""
        if not self.config['check_dns']:
            return None
        
        try:
            # 尝试解析域名
            dns.resolver.resolve(link.domain, 'A')
            return None  # DNS解析正常
        except:
            # DNS解析失败
            return ThreatResult(
                url=link.url,
                domain=link.domain,
                link_title=link.title,
                threat_level='high',
                threat_type='dns_failure',
                description=f'域名 {link.domain} DNS解析失败',
                evidence=f'无法解析域名: {link.domain}',
                recommendation='检查域名是否过期或已被劫持',
                timestamp=datetime.now().isoformat(),
                source_url=source_url
            )
    
    def _check_domain_whois(self, link: LinkInfo, source_url: str) -> Optional[ThreatResult]:
        """检查域名WHOIS信息"""
        if not self.config['check_whois']:
            return None
        
        try:
            domain_info = whois.whois(link.domain)
            
            # 检查域名是否过期
            if hasattr(domain_info, 'expiration_date'):
                exp_date = domain_info.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                
                if exp_date and exp_date < datetime.now():
                    return ThreatResult(
                        url=link.url,
                        domain=link.domain,
                        link_title=link.title,
                        threat_level='critical',
                        threat_type='expired_domain',
                        description=f'域名 {link.domain} 已过期',
                        evidence=f'过期时间: {exp_date}',
                        recommendation='立即移除过期域名的链接',
                        timestamp=datetime.now().isoformat(),
                        source_url=source_url
                    )
            
            # 检查域名状态
            if hasattr(domain_info, 'status'):
                status = domain_info.status
                if isinstance(status, list):
                    status = ' '.join(status)
                
                if 'for sale' in status.lower() or 'pending delete' in status.lower():
                    return ThreatResult(
                        url=link.url,
                        domain=link.domain,
                        link_title=link.title,
                        threat_level='high',
                        threat_type='domain_for_sale',
                        description=f'域名 {link.domain} 正在出售',
                        evidence=f'域名状态: {status}',
                        recommendation='检查域名是否被恶意收购',
                        timestamp=datetime.now().isoformat(),
                        source_url=source_url
                    )
        
        except Exception as e:
            self.logger.warning(f"WHOIS查询失败 {link.domain}: {str(e)}")
        
        return None
    
    def _check_website_content(self, link: LinkInfo, source_url: str) -> Optional[ThreatResult]:
        """检查网站内容 - 增强版"""
        if not self.config['check_content']:
            return None
        
        try:
            response = self.session.get(
                link.url, 
                timeout=self.config['timeout'],
                allow_redirects=True
            )
            
            if response.status_code != 200:
                return None
            
            # 获取页面内容
            content = self._decode_response_text(response).lower()
            title = ""
            description = ""
            
            # 提取页面标题和描述
            try:
                soup = BeautifulSoup(content, 'html.parser')
                title_tag = soup.find('title')
                if title_tag:
                    title = title_tag.get_text().lower()
                
                desc_tag = soup.find('meta', attrs={'name': 'description'})
                if desc_tag:
                    description = desc_tag.get('content', '').lower()
            except:
                pass
            
            # 合并所有文本内容进行分析
            all_text = f"{content} {title} {description}"
            
            # 检查恶意内容 - 使用更智能的匹配
            threat_scores = {}
            found_keywords = {}
            
            for category, keywords in self.malicious_keywords.items():
                score = 0
                matched_keywords = []
                used_keywords = set()  # 避免重复计算
                
                for keyword in keywords:
                    keyword_lower = keyword.lower()
                    
                    # 避免重复计算相同的关键词
                    if keyword_lower in used_keywords:
                        continue
                    used_keywords.add(keyword_lower)
                    
                    # 计算关键词出现次数
                    count = all_text.count(keyword_lower)
                    if count > 0:
                        # 根据关键词重要性给分
                        if keyword_lower in ['casino', 'bet', 'gamble', '博彩', '赌博', '赌场', '澳门', '老虎机']:
                            score += count * 3  # 博彩关键词权重更高
                        elif keyword_lower in ['porn', 'adult', 'sex', '色情', '成人', '按摩', '约会']:
                            score += count * 3  # 色情关键词权重更高
                        elif keyword_lower in ['torrent', 'download', '盗版', '下载', '免费电影']:
                            score += count * 2  # 盗版关键词权重中等
                        elif keyword_lower in ['f1', 'sports', 'football', '体育', '足球']:
                            score += count * 1  # 体育关键词权重较低
                        else:
                            score += count * 1  # 其他关键词权重较低
                        
                        matched_keywords.append(f"{keyword}({count})")
                
                if score > 0:
                    threat_scores[category] = score
                    found_keywords[category] = matched_keywords
            
            # 如果发现威胁，返回最高分的威胁
            if threat_scores:
                max_category = max(threat_scores, key=threat_scores.get)
                max_score = threat_scores[max_category]
                
                # 根据分数确定威胁等级
                if max_score >= 5:
                    threat_level = 'critical'
                elif max_score >= 3:
                    threat_level = 'high'
                elif max_score >= 2:
                    threat_level = 'medium'
                else:
                    threat_level = 'low'
                
                return ThreatResult(
                    url=link.url,
                    domain=link.domain,
                    link_title=link.title,
                    threat_level=threat_level,
                    threat_type=f'malicious_content_{max_category}',
                    description=f'检测到恶意内容: {max_category} (威胁分数: {max_score})',
                    evidence=f'发现关键词: {", ".join(found_keywords[max_category][:5])}',  # 只显示前5个关键词
                    recommendation='立即移除该链接，可能已被恶意劫持',
                    timestamp=datetime.now().isoformat(),
                    source_url=source_url
                )
        
        except Exception as e:
            self.logger.warning(f"内容检查失败 {link.url}: {str(e)}")
        
        return None
    
    def _get_threat_level_score(self, level: str) -> int:
        """获取威胁等级分数"""
        scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return scores.get(level, 0)
    
    def _deduplicate_results(self, results: List[ThreatResult]) -> List[ThreatResult]:
        """去重威胁结果"""
        seen = set()
        unique_results = []
        
        for result in results:
            # 创建唯一标识符：域名 + 威胁类型（不包含URL路径，避免同一域名的不同路径重复）
            key = f"{result.domain}|{result.threat_type}"
            
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
            else:
                # 如果已存在，保留威胁等级更高的结果
                for i, existing in enumerate(unique_results):
                    if (existing.domain == result.domain and 
                        existing.threat_type == result.threat_type):
                        
                        # 比较威胁等级，保留更高的
                        if self._get_threat_level_score(result.threat_level) > self._get_threat_level_score(existing.threat_level):
                            unique_results[i] = result
                        break
        
        return unique_results
    
    def scan_batch(self, urls: List[str]) -> List[ThreatResult]:
        """批量扫描URL"""
        all_results = []
        
        for url in tqdm(urls, desc="扫描进度"):
            try:
                results = self.scan_url(url)
                all_results.extend(results)
                
                # 添加延迟避免被限制
                time.sleep(self.config['delay'])

                # 可选自动保存：在每个URL后写入临时结果，便于中断恢复
                if self.config.get('autosave'):
                    try:
                        partial_file = self._make_partial_filename(self.config['output_file'])
                        self._save_partial_results(all_results, partial_file)
                        self.logger.info(f"已自动保存部分结果到: {partial_file}")
                    except Exception as save_err:
                        self.logger.warning(f"自动保存部分结果失败: {str(save_err)}")
            except KeyboardInterrupt:
                # 在用户中断时保留已完成部分
                self.logger.warning("扫描被中断，已完成部分结果将被保存")
                break
            except Exception as e:
                self.logger.error(f"扫描 {url} 时发生异常: {str(e)}")
                continue
        
        # 去重处理 - 基于域名与威胁类型
        unique_results = self._deduplicate_results(all_results)
        return unique_results

    def _make_partial_filename(self, output_file: str) -> str:
        """基于最终输出文件名生成部分结果文件名"""
        base, ext = os.path.splitext(output_file)
        timestamp = datetime.now().strftime("%H%M%S")
        return f"{base}.partial.{timestamp}{ext or '.json'}"

    def _save_partial_results(self, results: List[ThreatResult], output_file: str) -> None:
        """保存部分结果到文件（简化版报告）"""
        # 确保输出目录存在
        output_dir = 'output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 构建完整的输出路径
        output_path = os.path.join(output_dir, output_file)
        
        stats = {
            'total_threats': len(results),
            'by_level': {},
            'by_type': {}
        }
        for r in results:
            stats['by_level'][r.threat_level] = stats['by_level'].get(r.threat_level, 0) + 1
            stats['by_type'][r.threat_type] = stats['by_type'].get(r.threat_type, 0) + 1
        payload = {
            'partial': True,
            'timestamp': datetime.now().isoformat(),
            'statistics': stats,
            'threats': [asdict(r) for r in results]
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    
    def generate_report(self, results: List[ThreatResult], output_file: str = None):
        """生成报告"""
        if not output_file:
            output_file = self.config['output_file']
        
        # 确保输出目录存在
        output_dir = 'output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            self.logger.info(f"创建输出目录: {output_dir}")
        
        # 构建完整的输出路径
        output_path = os.path.join(output_dir, output_file)
        
        # 统计信息
        stats = {
            'total_scanned': len(set(r.url for r in results)),
            'total_threats': len(results),
            'threat_levels': {},
            'threat_types': {}
        }
        
        for result in results:
            # 统计威胁等级
            stats['threat_levels'][result.threat_level] = stats['threat_levels'].get(result.threat_level, 0) + 1
            # 统计威胁类型
            stats['threat_types'][result.threat_type] = stats['threat_types'].get(result.threat_type, 0) + 1
        
        # 生成报告数据
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'config': self.config
            },
            'statistics': stats,
            'threats': [asdict(result) for result in results]
        }
        
        # 保存报告
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        # 额外输出：将报告中的威胁URL单独保存为txt，便于批量打开
        try:
            base, _ext = os.path.splitext(output_file)
            urls_txt = os.path.join(output_dir, f"{base}_urls.txt")
            # 仅保留唯一URL（去重），一行一个
            unique_urls = []
            seen = set()
            for r in results:
                if r.url not in seen:
                    seen.add(r.url)
                    unique_urls.append(r.url)
            with open(urls_txt, 'w', encoding='utf-8') as uf:
                uf.write("\n".join(unique_urls))
            self.logger.info(f"威胁URL列表已保存到: {urls_txt}")
        except Exception as e:
            self.logger.warning(f"保存URL列表失败: {str(e)}")

        self.logger.info(f"报告已保存到: {output_path}")
        return report
    
    def print_summary(self, results: List[ThreatResult]):
        """打印扫描摘要"""
        if not results:
            print(f"{Fore.GREEN}✓ 未发现威胁")
            return
        
        # 按威胁等级排序（critical > high > medium > low）
        threat_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        sorted_results = sorted(results, key=lambda x: threat_order.get(x.threat_level, 0), reverse=True)
        
        print(f"\n{Fore.RED}⚠ 发现 {len(sorted_results)} 个威胁:")
        print("=" * 80)
        
        for result in sorted_results:
            color = {
                'low': Fore.YELLOW,
                'medium': Fore.YELLOW,
                'high': Fore.RED,
                'critical': Fore.RED + Style.BRIGHT
            }.get(result.threat_level, Fore.WHITE)
            
            print(f"{color}[{result.threat_level.upper()}] {result.url}")
            print(f"  域名: {result.domain}")
            print(f"  标题: {result.link_title}")
            print(f"  来源: {result.source_url}")
            print(f"  类型: {result.threat_type}")
            print(f"  描述: {result.description}")
            print(f"  证据: {result.evidence}")
            print(f"  建议: {result.recommendation}")
            print("-" * 80)


def main():
    """主函数"""
    # 显示启动横幅
    show_banner()
    
    parser = argparse.ArgumentParser(description='ThreatLink - 威胁情报检测工具')
    parser.add_argument('-u', '--url', help='指定单个URL进行扫描')
    parser.add_argument('-r', '--request', help='从文件读取URL列表进行批量扫描')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间（默认10秒）')
    parser.add_argument('-d', '--delay', type=float, default=1, help='请求间隔时间（默认1秒）')
    parser.add_argument('--no-dns', action='store_true', help='跳过DNS检查')
    parser.add_argument('--enable-whois', action='store_true', help='启用WHOIS检查（默认关闭）')
    parser.add_argument('--autosave', action='store_true', help='在批量扫描时为每个URL自动保存部分结果')
    parser.add_argument('--no-content', action='store_true', help='跳过内容检查')
    parser.add_argument('--verbose', '-v', action='store_true', help='显示详细输出')
    
    args = parser.parse_args()
    
    # 构建配置
    config = {
        'timeout': args.timeout,
        'delay': args.delay,
        'check_dns': not args.no_dns,
        'check_whois': args.enable_whois,  # 默认关闭，需要显式启用
        'check_content': not args.no_content,
        'output_file': args.output or f'threat_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
        'verbose': args.verbose,
        'autosave': args.autosave
    }
    
    # 获取URL列表
    urls = []
    
    # 处理单个URL (-u)
    if args.url:
        urls.append(args.url)
    
    # 处理URL列表文件 (-r)
    if args.request:
        try:
            with open(args.request, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # 忽略空行和注释
                        # 自动添加http://前缀（如果没有协议）
                        if not line.startswith(('http://', 'https://')):
                            line = 'http://' + line
                        urls.append(line)
            
            if config['verbose']:
                print(f"{Fore.GREEN}✓ 从文件 {args.request} 加载了 {len(urls)} 个URL")
                
        except FileNotFoundError:
            print(f"{Fore.RED}错误: 文件 {args.request} 不存在")
            return
        except Exception as e:
            print(f"{Fore.RED}错误: 读取文件时出错 - {str(e)}")
            return
    
    if not urls:
        print(f"{Fore.RED}错误: 请使用 -u 指定单个URL 或 -r 指定URL列表文件")
        print(f"{Fore.YELLOW}示例:")
        print(f"  python threat_intelligence_scanner.py -u http://example.com")
        print(f"  python threat_intelligence_scanner.py -r urls.txt")
        parser.print_help()
        return
    
    # 创建扫描器并开始扫描
    scanner = ThreatIntelligenceScanner(config)
    
    if config['verbose']:
        print(f"{Fore.CYAN}开始扫描 {len(urls)} 个URL...")
        print(f"{Fore.CYAN}配置: 超时={config['timeout']}s, 间隔={config['delay']}s")
        print(f"{Fore.CYAN}检查项目: DNS={config['check_dns']}, WHOIS={config['check_whois']}, 内容={config['check_content']}")
        print("=" * 60)
    
    try:
        results = scanner.scan_batch(urls)
    except KeyboardInterrupt:
        # 用户主动中断，仍旧生成报告，包含已完成的部分
        print(f"\n{Fore.YELLOW}扫描被中断，正在保存已完成的部分结果……")
        results = []  # 若扫描函数内部未返回，使用空列表占位，由后续自动保存逻辑处理
    
    # 生成报告
    # 无论是否中断，都尽量输出已收集的结果报告
    if results:
        scanner.generate_report(results, args.output)
        scanner.print_summary(results)
    else:
        # 如果结果为空，但启用了自动保存，提示用户查看partial文件
        if config.get('autosave'):
            print(f"{Fore.CYAN}请在程序目录中查看以 .partial.* 结尾的临时结果文件")
        else:
            print(f"{Fore.YELLOW}没有可用结果可保存。如需在扫描过程中间歇保存，请开启 --autosave 选项")
    
    if config['verbose']:
        # 构建完整的输出路径
        output_dir = 'output'
        output_path = os.path.join(output_dir, config['output_file'])
        urls_txt_path = os.path.join(output_dir, config['output_file'].replace('.json', '_urls.txt'))
        
        print(f"\n{Fore.GREEN}ThreatLink 扫描完成！报告已保存到: {output_path}")
        print(f"{Fore.CYAN}提示: 查看 {urls_txt_path} 获取威胁URL列表")


if __name__ == '__main__':
    main()
