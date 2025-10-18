# ThreatLinkScan - 威胁情报检测工具

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

一款用于检测网站外链劫持漏洞的 Python 工具，聚焦外链内容安全与可疑场景识别，支持大规模批量扫描、断点中断后保留部分结果、URL 导出等能力。

**by Att@ckxu** | 专业安全研究工具

## 功能特性（最新版）

- 🔍 **智能外链提取**: 自动分析网页HTML源码，提取所有外部链接
- 🚨 **精准威胁检测**:
  - DNS 解析状态检查（默认开启）
  - 网站内容恶意性检测（博彩、色情、盗版、体育、钓鱼、恶意下载等）
  - 智能关键词匹配与权重评分
- 🧾 **WHOIS 检查可选**：默认关闭，可用 `--enable-whois` 打开
- 🧠 **乱码修复**：自动推断编码，修复中文标题乱码
- 🏷️ **外链信息增强**：报告包含 `source_url`（来源页面）、`link_title`（外链标题）
- 📊 **详细报告生成**: 生成JSON格式的详细威胁分析报告
- 🎯 **精确定位**: 识别外链在页面中的位置（页脚、侧边栏等）
- ⚡ **批量扫描**: 支持批量处理多个URL
- 🛡️ **威胁分级**: 按严重程度对威胁进行分类（低、中、高、严重）
- 🔄 **智能去重**: 基于“域名+威胁类型”去重，避免冗余
- 🧯 **误报抑制**：默认跳过 `.edu.cn`、`.gov.cn` 以及带 `edu/gov` 标签的域名外链（可配置）
- 📦 **断点友好**：`--autosave` 批量时每个 URL 后自动保存阶段性结果；Ctrl+C 中断也会保留已完成部分
- 📤 **URL 导出**：生成报告的同时导出一个 `_urls.txt`，便于批量打开威胁 URL
- 🎨 **彩色输出**: 按威胁等级显示不同颜色的结果

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 使用方法

#### 主工具 - ThreatLinkScan.py

```bash
# 扫描单个URL
python ThreatLinkScan.py -u https://example.com

# 从文件读取URL列表进行批量扫描
python ThreatLinkScan.py -r urls.txt

# 指定输出文件
python ThreatLinkScan.py -u https://example.com -o report.json

# 显示详细输出
python ThreatLinkScan.py -u https://example.com -v
```


### 批量扫描与断点续扫

```bash
# 批量扫描 + 自动阶段性保存 + 详细输出
python ThreatLinkScan.py -r urls.txt --autosave -v

# 中途 Ctrl+C 终止时：
# - 已完成部分会被保存
# - 若开启了 --autosave，还会在同目录产出以 .partial.<时分秒>.json 结尾的阶段性文件
```

### 高级选项

```bash
# 设置请求超时时间
python ThreatLinkScan.py -u https://example.com -t 15

# 设置请求间隔
python ThreatLinkScan.py -u https://example.com -d 2

# 跳过某些检查
python ThreatLinkScan.py -u https://example.com --no-dns --no-whois

# 启用WHOIS检查
python ThreatLinkScan.py -u https://example.com --enable-whois

# 批量扫描并显示详细输出
python ThreatLinkScan.py -r urls.txt -v -o detailed_report.json
```

### 参数说明

- `-u, --url`: 指定单个URL进行扫描
- `-r, --request`: 从文件读取URL列表进行批量扫描
- `-o, --output`: 输出文件路径
- `-t, --timeout`: 请求超时时间（默认10秒）
- `-d, --delay`: 请求间隔时间（默认1秒）
- `-v, --verbose`: 显示详细输出
- `--no-dns`: 跳过DNS检查
- `--enable-whois`: 启用WHOIS检查（默认关闭）
- `--no-content`: 跳过内容检查
- `--autosave`: 批量时在每个 URL 后自动保存阶段性结果

## 📁 项目结构

```
威胁情报/
├── ThreatLinkScan.py          # 主扫描工具（命令行版本）
├── config.json               # 配置文件
├── requirements.txt          # Python依赖包
├── README.md                 # 项目说明文档
├── url.txt                   # URL示例文件
└── output/                   # 扫描结果输出目录
    ├── threat_scan_*.json    # JSON格式威胁报告
    └── threat_scan_*_urls.txt # 威胁URL列表
```

## ✨ 最新特性

### 🎯 智能误报抑制
- **学校相关链接排除**：自动跳过标题包含"中学"、"大学"、"教育"等关键词的链接
- **教育机构域名排除**：默认排除`.edu.cn`、`.gov.cn`等教育政府域名
- **内网IP排除**：自动跳过内网IP地址的链接

### 🔧 增强功能
- **中文编码修复**：自动检测和修复中文标题乱码问题
- **智能去重**：基于域名+威胁类型的去重机制
- **威胁分级**：四级威胁等级（低、中、高、严重）
- **断点续扫**：支持扫描中断后继续完成剩余任务

## 🛡️ 威胁检测能力

## 威胁类型

工具能够检测以下类型的威胁：

### 1. DNS解析失败
- **威胁等级**: 高
- **描述**: 域名无法解析，可能已过期或被劫持
- **建议**: 检查域名状态，移除无效链接

### 2. 域名过期
- **威胁等级**: 严重
- **描述**: 域名已过期，可能被恶意收购
- **建议**: 立即移除过期域名的链接

### 3. 域名出售
- **威胁等级**: 高
- **描述**: 域名正在出售，存在被恶意收购的风险
- **建议**: 检查域名是否被恶意收购

### 4. 恶意内容
- **威胁等级**: 严重
- **描述**: 检测到色情、赌博、盗版等恶意内容
- **建议**: 立即移除该链接，可能已被恶意劫持

## 输出格式

工具会生成 JSON 格式的详细报告，包含：

```json
{
  "scan_info": {
    "timestamp": "2024-01-01T12:00:00",
    "scanner_version": "1.0.0",
    "config": {...}
  },
  "statistics": {
    "total_scanned": 5,
    "total_threats": 3,
    "threat_levels": {
      "high": 2,
      "critical": 1
    },
    "threat_types": {
      "dns_failure": 1,
      "expired_domain": 1,
      "malicious_content_porn": 1
    }
  },
  "threats": [
    {
      "url": "https://extern.example.com/path",
      "domain": "extern.example.com",
      "link_title": "外链标题",
      "threat_level": "critical",
      "threat_type": "malicious_content_porn",
      "description": "检测到恶意内容: porn",
      "evidence": "发现关键词: porn",
      "recommendation": "立即移除该链接，可能已被恶意劫持",
      "timestamp": "2024-01-01T12:00:00",
      "source_url": "https://source.example.com"
    }
  ]
}
```

## 配置说明

可在代码默认配置中调整（或后续扩展命令行覆盖）：

- `exclude_domain_suffixes`: 精确后缀排除（默认：`.edu.cn`, `.gov.cn`）
- `exclude_domains_with_labels`: 标签排除（默认：`edu`, `gov`）
- `autosave`: 是否在批量时自动保存阶段性结果
- `check_dns` / `check_whois` / `check_content`: 各检测开关
- `timeout` / `delay`: 请求超时与间隔
- `malicious_keywords`: 恶意内容关键词集合（可自行扩展）

## 使用场景

1. **SRC漏洞挖掘**: 检测目标网站的外链劫持漏洞
2. **安全审计**: 定期检查网站外链的安全性
3. **威胁情报收集**: 收集和分析恶意域名信息
4. **合规检查**: 确保网站外链符合安全标准

## 注意事项

1. 请遵守相关法律法规，仅用于授权的安全测试
2. 扫描时请控制频率，避免对目标网站造成过大压力
3. 某些网站可能有反爬虫机制，建议使用代理或调整请求间隔
4. WHOIS 查询可能受到限制，建议合理设置查询频率（默认关闭）
5. 若需进一步降低误报，可扩展 `exclude_domain_suffixes`（如 `.edu`, `.gov`, `.edu.hk` 等）或微调关键词权重

## 🤝 贡献指南

欢迎为这个项目做出贡献！以下是参与方式：

### 报告问题
- 使用 [GitHub Issues](https://github.com/hhhanxx/ThreatLinkScan/issues) 报告bug或提出功能建议
- 请提供详细的复现步骤和环境信息

### 提交代码
1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 开发规范
- 遵循 PEP 8 代码风格
- 添加适当的注释和文档
- 确保所有测试通过

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## ⚠️ 免责声明

本工具仅用于授权的安全测试和教育目的。使用者需遵守当地法律法规，对使用本工具造成的任何后果负责。

**请勿用于非法用途！**

## 📞 联系作者

- **作者**: Att@ckxu
- **邮箱**: [请通过GitHub Issues联系]
- **GitHub**: [https://github.com/hhhanxx](https://github.com/hhhanxx)

---

⭐ 如果这个项目对您有帮助，请给个Star支持一下！
