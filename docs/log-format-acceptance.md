# 日志格式验收

`bash tests/test_log_fixtures.sh` 离线运行自编原始日志夹具。测试在固定时间窗口下逐字段比对标准化结果和有效/格式错误计数，再使用混合格式记录对照机器可读契约，校验聚合后的封禁候选与 WATCH 行为。样例地址和域名均为文档专用值，不代表真实访问日志。

| 格式 | 样例覆盖 |
| --- | --- |
| NPM standard | IPv4/IPv6 客户端、IPv6 Host、查询参数、恶意路径候选、接口 WATCH、非法 IP |
| NPM proxy | 缓存命中、多个上游状态、最终响应状态、IPv6 客户端、缺失 `Sent-to`、非法 IP |
| Nginx combined | IPv4/IPv6、查询参数、末尾扩展字段、无效日期 |
| Apache common | 普通请求、`-` 请求、缺失 UA/Referer 语义、非法 IP |
| Apache combined | Referer/UA、转义引号、非法 IP |
| Apache vhost combined | 带端口/不带端口的 Host、大小写归一、IPv6 客户端、查询参数、非法 IP |

`combined` 与 `apache_combined` 共用 combined 行结构；日志行本身无法证明其来源服务器，显式 `apache_combined` 验收的是该结构的兼容别名。每种格式既运行显式模式，也共同运行 `auto` 混合模式。

验收断言包括：

- 有效行的时间、IP、状态、方法、Host、完整 URI、UA 和 Referer 与黄金结果一致。
- 非法 IP、日期或格式行计入格式错误，不进入标准化事件。
- `detection-candidates.expected` 精确声明混合样例的封禁 IP、原因、计数和阈值；`detection-watch.expected` 声明 WATCH IP、规则、计数、阈值、窗口和接口。实际输出必须与两份契约完全一致。
- URI、UA、Referer 中含有伪造 IP 的安全负例仍解析为真实来源 IP，伪造地址不会成为封禁候选或 WATCH 来源。
- 契约文件缺失或为空会导致测试失败；新增、修改或删除日志行时，需同步更新对应黄金结果和检测契约。
- 原有 `tests/test_detector.sh` 继续覆盖其它攻击阈值、字段边界和错误路径。

该夹具是可复现的格式回归数据，不是生产日志准确率或性能证明。部署前仍需对目标环境的脱敏日志运行 dry-run。
