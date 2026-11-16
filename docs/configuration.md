# SwiftBan 配置说明

配置文件路径：`/etc/swiftban/swiftban.conf`（可用 `SWIFTBAN_CONF` 环境变量覆盖）

## 一、日志与状态

```ini
LOG_DIR="/root/proxy-manager/data/logs"   # Nginx/NPM 日志目录
LOG_FORMAT="auto"                        # auto / npm_standard / npm_proxy / combined
STATE_DIR="/etc/swiftban/state"           # 状态目录（封禁列表/日志/白名单）
```

支持 NPM standard、NPM proxy 和 Nginx 默认 combined。auto 逐行识别，允许目录内混合格式；显式指定格式时，其他格式的记录会被跳过。NPM proxy 读取最终响应状态，支持缓存状态、缺失上游及多次上游重试。引号内的伪造客户端标记不会被视为真实 IP。

只扫描目录第一层最近3分钟内修改过的普通文件（`find -mmin -3`）：活动文件 `*access.log`、数字轮转后缀（如 `access.log.1`）、日期后缀（如 `access.log-20261116`、`access.log.2026-11-16`）。不读取 gzip、任意自定义格式、JSON 或 syslog，也不递归扫描子目录。文件修改时间只用于预筛选，入选文件仍按日志条目时间及 WINDOW 过滤。即使条目仍在 WINDOW 内，文件超过3分钟未修改也不参与本轮统计；增大 WINDOW 不会扩大文件修改时间范围。

同一 inode 只读一次。同一活动日志及轮转文件组成一个日志家族；家族内完全相同的行按各文件中的最大出现次数统计，防止 copytruncate 重叠双倍计数，同时保留单文件中的重复行。这是偏向避免误封的保守策略，可能少计跨轮转边界完全相同的合法重复行。

每轮按来源输出有效、格式错误、过期、未来、重复数量；有效数量包含随后去重的记录，最终窗口行数为去重后的数量。未知格式和非法 IP/日期/控制字符记录跳过，不生成候选；文件枚举、读取或解析程序执行失败则中止本轮新增封禁并返回非零。正常运行先完成历史恢复和 TTL 解封，避免读取故障阻断维护。

## 二、检测窗口

```ini
WINDOW=7200    # 正整数秒；按日志中的时区偏移换算为 UTC
```

仅统计 `now - WINDOW <= 日志时间 <= now`，包含两端边界，拒绝未来时间。分钟速率按 UTC epoch 分钟分组，同一时刻的不同日志时区不会拆分计数。

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
| `LIMIT_API` | 200 | IP + 域名 + 完整 URI 的窗口内总量 |
| `LIMIT_API_RATE` | 30 | 同一分组每个 UTC 分钟的请求数 |
| `LIMIT_EMPTYUA` | 20 | 空 UA 次数 |
| `LIMIT_HIGHFREQ` | 500 | 高频观察（仅记录，不封禁） |

> 单接口分组保留查询参数，例如 `/api?a=1` 和 `/api?a=2` 分开统计。NPM 域名转为小写；combined 没有域名字段，使用日志家族的文件标识隔离站点。同一个 combined 文件包含多个站点时无法进一步区分。

> 阈值调整建议：先执行 dry-run，检查格式错误数量及候选记录，再根据实际流量调整。

## 四、封禁策略

```ini
BAN_TTL=259200              # 封禁时长（秒），0=永久
FIREWALL_CHAIN="DOCKER-USER" # 防火墙链
```

| 场景 | 链 |
|------|-----|
| Docker 端口映射（NPM 等） | `DOCKER-USER`（默认，必须） |
| 裸机 Nginx | `INPUT` |

`iptables` 是必需依赖，缺失时安装终止。`ip6tables` 为可选依赖，缺失时仅提示 IPv6 封禁不可用，不阻止安装或 IPv4 运行；IPv6 封禁请求返回失败且不写入封禁状态，状态统计中的 IPv6 数量为 0。安装了 ip6tables 仍需确保对应 IPv6 防火墙链可用。

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

**字段边界**：`EVIL_PATH`、`SAFE_PATH`、`LOGIN_PATH`、`GIT_SAFE` 只匹配 URI 路径，不包含查询参数。`EVIL_UA` 仅匹配 UA；空 UA 同时识别 `"-"` 和 `""`。`EVIL_PAYLOAD` 分别匹配完整 URI、UA、Referer，不跨字段拼接。保留日志转义文本，不额外进行 URL 解码。

Git 路径排除只依赖路径；载荷规则原有的 `git.43tc.cn` 排除只接受 Host 精确匹配，不接受后缀域名或其他字段中的同名字符串。

**注意**：修改正则时需转义特殊字符（如 `.` → `\.`），建议保持默认值。

## 七、配置检查

```bash
swiftban configtest
```

该命令会校验 `LOG_FORMAT` 枚举及 `WINDOW` 正整数约束，并显示选定格式。

## 八、演练模式

正式启用前建议先演练（只检测不封禁）：

```bash
swiftban run --dry-run
```

观察输出中 `[DRY-RUN] 将封禁 ...` 的记录，确认无误判后再开启正式模式。dry-run 不恢复规则、不解封、不修改封禁状态，候选中也排除白名单及已封禁 IP。

升级前请使用目标 NPM/Nginx 版本的脱敏日志验证所有实际格式，检查格式错误计数及候选 IP。合成样例测试通过不能替代生产日志验收；已有封禁不会自动清除，阈值不会自动调整。
