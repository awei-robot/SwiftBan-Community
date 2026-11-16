<div align="center">

# 🛡️ SwiftBan

**基于 Nginx 日志的实时攻击检测与自动封禁系统**

轻量级 · 零依赖 · 零误封 的自建站 WAF

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](VERSION)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash%20%2B%20gawk-orange.svg)]()

[官网](https://awei-robot.github.io/SwiftBan-Community/) · [商业版](https://github.com/awei-robot/SwiftBan) · [问题反馈](https://github.com/awei-robot/SwiftBan-Community/issues)

</div>

---

## 🎯 这是什么

SwiftBan 通过分析 Nginx / Nginx Proxy Manager 访问日志，实时识别攻击行为（扫描、注入、爆破、CC），并自动用 iptables 封禁恶意 IP。

**核心理念：只封禁明确攻击特征，绝不误伤正常业务流量。**

已在生产环境（腾讯云 NPM + Docker）长期运行，累计拦截数千次攻击，**零误封记录**。

## ✨ 特性

- 🔍 **11 个检测维度**：域名扫描（444）、404/400 扫描、恶意路径、漏洞载荷（SQL 注入/XSS/Log4j/路径穿越）、可疑 UA、登录爆破、单接口高频/速率、空 UA、高频观察
- 🔥 **自动封禁**：iptables/ip6tables 双栈，`DOCKER-USER` 链原生兼容 Docker 端口映射
- 🛡️ **双层白名单**：内置内网 IP + 自定义文件（支持 CIDR 网段，动态生效）
- ⏱️ **自动解封**：TTL 过期自动恢复（默认 3 天）
- 💾 **状态持久化**：服务器重启/规则丢失后自动恢复
- 📦 **零依赖**：纯 Bash + GNU 工具（gawk），单机 5 分钟部署
- 🔇 **防日志噪音**：白名单 IP 静默跳过
- 🌐 **时区安全**：按日志时区偏移换算 UTC，拒绝未来时间，精确窗口统计
- 🧾 **日志格式**：NPM standard/proxy 与 Nginx combined 自动识别，支持未压缩轮转文件

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/awei-robot/SwiftBan-Community.git
cd SwiftBan-Community
sudo ./install/install.sh
```

依赖：Linux + root + iptables + gawk（awk 需支持 mktime 及区间正则）。安装脚本自带依赖检查。

`iptables` 必须存在；`ip6tables` 可选，缺失时提示 IPv6 封禁不可用，IPv4 功能正常。未成功执行的 IPv6 封禁不会写入封禁状态。

### 配置

编辑 `/etc/swiftban/swiftban.conf`：

```ini
LOG_DIR=/root/proxy-manager/data/logs   # Nginx/NPM 日志目录
LOG_FORMAT=auto                         # auto / npm_standard / npm_proxy / combined
BAN_TTL=259200                          # 封禁时长（秒，0=永久）
WHITELIST=127.0.0.1,::1,192.168.224.1   # 白名单
```

### 使用

```bash
swiftban run --dry-run     # 演练模式：只检测不封禁（建议先跑 1-2 天观察）
swiftban run               # 正式检测（cron 每分钟自动执行）
swiftban status            # 查看运行状态
swiftban list              # 列出封禁 IP
swiftban ban 1.2.3.4       # 手动封禁
swiftban unban 1.2.3.4     # 手动解封
swiftban whitelist add 10.0.0.0/8   # 白名单管理
```

### 定时任务

```bash
swiftban install-cron      # 安装每分钟执行 cron（或使用 systemd timer，见 deploy/）
```

## 📊 版本对比

| 能力 | 社区版 | [商业版](https://github.com/awei-robot/SwiftBan) |
|------|:---:|:---:|
| 11 维度检测 + iptables 双栈封禁 | ✅ | ✅ |
| CLI 管理 / cron 定时 | ✅ | ✅ |
| **Go 单二进制**（零依赖，含 Linux/Windows） | — | ✅ |
| **Web 管理台**（仪表盘/封禁/白名单，Basic Auth） | — | ✅ |
| **Windows 服务版**（RDP 爆破防护） | — | ✅ |
| **多机集中控制台**（Enterprise） | — | ✅ |
| license 授权 / 规则订阅 | — | ✅ |

> 商业版面向需要 Web 管理界面、Windows 服务器防护、多机集中管理的场景。社区版永久免费、MIT 开源。

## 🏗️ 架构

```
Nginx/NPM 活动日志及未压缩轮转文件
      │ 第一层目录仅收集最近3分钟修改的文件，轮转重叠去重
      ▼
统一字段解析 → 按日志时区转 UTC → WINDOW 时间过滤
      ▼
字段限定的特征统计（单次 awk 聚合）
      ▼
白名单检查 → 阈值决策 → 封禁/观察
      ▼
iptables -I DOCKER-USER -s IP -j DROP
      ▼
banlist.txt 持久化 / TTL 自动解封 / 规则自动恢复
```

详细设计见 [docs/architecture.md](docs/architecture.md)，配置项见 [docs/configuration.md](docs/configuration.md)。

只支持上述已定义格式，未知或非法记录会跳过并报告数量；读取或解析程序失败时停止本轮新增封禁。仅读取最近3分钟修改的活动及未压缩轮转文件，入选文件仍按条目时间和 WINDOW 过滤；较早停止写入的文件不参与本轮统计。gzip、JSON、syslog 和任意自定义格式暂不支持。接口按 IP + 域名 + 完整 URI（保留查询参数）分组；combined 使用日志文件家族隔离站点。

上线前请在目标版本的脱敏真实日志上执行 dry-run，检查格式错误及封禁候选。历史封禁及阈值不会自动调整。

## 🧪 测试

```bash
bash tests/test_detector.sh     # 白名单、格式/时区、字段边界、轮转、决策和故障回归
shellcheck bin/swiftban.sh lib/*.sh tests/test_detector.sh install/install.sh
```

macOS 测试会优先使用 gawk；awk 缺少 mktime 或区间正则支持时测试失败，不会跳过时间解析检查。测试中的防火墙操作均使用 mock。

## 📋 路线图

详见 [docs/roadmap.md](docs/roadmap.md)。

## 📄 许可证

MIT License

## 🙏 致谢

在腾讯云 NPM + Docker 生产环境长期验证，累计拦截数千次攻击，零误封。
