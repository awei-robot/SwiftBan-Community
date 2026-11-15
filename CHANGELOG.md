# 更新日志

本文件记录 SwiftBan 的版本变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

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
