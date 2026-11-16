# 更新日志

本文件记录 SwiftBan 的版本变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [Unreleased]

### 修复

- 统一解析 NPM standard/proxy 和 Nginx combined；修复伪造客户端标记、最终状态码及 URI 字段错位导致的错误封禁候选。
- 按日志时区偏移计算 UTC 窗口，拒绝未来及非法日期；接口按 IP、域名和完整 URI 分组。
- 限定路径、UA、载荷规则的字段边界，兼容空字符串 UA 及尾部扩展字段。
- 收集未压缩数字/日期轮转文件，去除同 inode 和家族重叠计数；读取或解析失败时停止新增封禁。
- 文件收集限定为最近3分钟内修改的活动及未压缩轮转文件，入选文件继续按条目时间和 WINDOW 过滤。
- 扫描前恢复历史规则及清理过期状态；演练排除白名单及已封禁 IP，不修改封禁状态。
- 修正安装模块目标目录与 CLI 加载目录不一致的问题。
- iptables 保持必需，ip6tables 改为可选；缺失时提示 IPv6 封禁不可用，IPv4 功能正常，IPv6 封禁失败不写入状态。

### 新增

- `LOG_FORMAT=auto|npm_standard|npm_proxy|combined` 配置及逐来源解析统计。
- 格式、安全边界、时区、轮转及完整运行故障回归测试；时间解析不可跳过。

## [1.0.0] - 2026-11-15

### 新增

**检测引擎（11 维度）**
- 域名扫描检测（NPM 444 状态码）
- 扫描探测检测（404/400 高频，排除地图瓦片等正常路径）
- 恶意路径/敏感文件检测（wp-admin/.env/.git/.sql/backup 等）
- 漏洞载荷检测（SQL 注入/XSS/Log4j/路径穿越/命令注入）
- 可疑 UA 检测（sqlmap/nikto/zgrab 等 14 种扫描器）
- 登录爆破检测（登录路径 401/403，精确匹配避免误伤）
- 单接口高频检测（2 小时窗口总量）
- 单接口速率检测（1 分钟窗口，CC 攻击实时捕获）
- 空 UA 检测（精确提取行尾 UA 字段）
- 高频观察模式（仅记录不封禁）
- IPv6 双栈支持

**封禁与白名单**
- iptables/ip6tables 双栈封禁（DOCKER-USER 链，兼容 Docker 端口映射）
- 双层白名单：内置 + 独立文件（支持 IP/CIDR/注释，动态生效）
- TTL 自动解封（默认 3 天）
- 状态持久化与规则自动恢复
- 白名单静默跳过（无日志噪音）

**CLI 与部署**
- 完整 CLI：run/status/list/ban/unban/whitelist/configtest
- 演练模式（--dry-run）
- 一键安装脚本（含依赖检查、cron 安装）
- cron 每分钟定时执行
- 模块化架构（logger/firewall/whitelist/detector）

**文档与测试**
- 产品 README、架构文档、配置文档、路线图
- 单元测试（白名单 CIDR、时间过滤）

### 生产验证

- 部署环境：腾讯云 2 台服务器（NPM + Docker）
- 累计拦截数千次攻击（域名扫描、webshell 扫描、注入、爆破）
- 零误封记录（特征驱动 + 白名单机制）

---

## 规划

见 [docs/roadmap.md](docs/roadmap.md)
