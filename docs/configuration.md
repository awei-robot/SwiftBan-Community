# SwiftBan 配置说明

配置文件路径：`/etc/swiftban/swiftban.conf`（可用 `SWIFTBAN_CONF` 环境变量覆盖）

## 一、日志与状态

```ini
LOG_DIR="/root/proxy-manager/data/logs"   # Nginx/NPM 日志目录
STATE_DIR="/etc/swiftban/state"           # 状态目录（封禁列表/日志/白名单）
```

## 二、检测窗口

```ini
WINDOW=7200    # 时间窗口（秒）。日志为 UTC，脚本自动按 UTC 计算
```

| 窗口 | 适用场景 |
|------|---------|
| 300 | 5 分钟，快速响应（阈值需相应降低） |
| 7200 | **默认**，2 小时，平衡灵敏度与误封 |
| 86400 | 24 小时，宽松模式 |

## 三、封禁阈值

| 参数 | 默认 | 说明 |
|------|------|------|
| `LIMIT_444` | 10 | 域名扫描（444 次数） |
| `LIMIT_SCAN` | 100 | 404/400 扫描次数 |
| `LIMIT_EVILPATH` | 3 | 恶意路径/敏感文件次数 |
| `LIMIT_PAYLOAD` | 2 | 漏洞载荷次数 |
| `LIMIT_UA` | 5 | 可疑 UA 次数 |
| `LIMIT_AUTH` | 20 | 登录爆破（登录路径 401/403） |
| `LIMIT_API` | 200 | 单接口高频（总量/窗口） |
| `LIMIT_API_RATE` | 30 | 单接口速率（次/分钟） |
| `LIMIT_EMPTYUA` | 20 | 空 UA 次数 |
| `LIMIT_HIGHFREQ` | 500 | 高频观察（仅记录，不封禁） |

> 阈值调整建议：先以默认值运行观察 1-2 天，根据 WATCH 记录调整。

## 四、封禁策略

```ini
BAN_TTL=259200              # 封禁时长（秒），0=永久
FIREWALL_CHAIN="DOCKER-USER" # 防火墙链
```

| 场景 | 链 |
|------|-----|
| Docker 端口映射（NPM 等） | `DOCKER-USER`（默认，必须） |
| 裸机 Nginx | `INPUT` |

## 五、白名单

```ini
# 内置（逗号分隔，精确匹配）
WHITELIST="127.0.0.1,::1,192.168.224.1,172.17.0.1"

# 独立文件（IP/CIDR，动态生效，优先级更高）
WHITELIST_FILE="/etc/swiftban/state/whitelist.txt"
```

白名单文件格式：
```
# 注释
192.168.1.100          # 单 IP
10.0.0.0/8             # 整个网段
203.0.113.0/24         # 特定网段
```

## 六、特征库

```ini
SAFE_PATH='/TDT/'       # 正常路径（404 不计入扫描）
GIT_SAFE='git-upload-pack|git-receive-pack|info/refs'
EVIL_PATH='...'         # 恶意路径正则
EVIL_PAYLOAD='...'      # 漏洞载荷正则
EVIL_UA='...'           # 可疑 UA 正则
LOGIN_PATH='login|signin|auth|token'
```

**注意**：修改正则时需转义特殊字符（如 `.` → `\.`），建议保持默认值。

## 七、配置检查

```bash
swiftban configtest
```

## 八、演练模式

正式启用前建议先演练（只检测不封禁）：

```bash
swiftban run --dry-run
```

观察输出中 `[DRY-RUN] 将封禁 ...` 的记录，确认无误判后再开启正式模式。
