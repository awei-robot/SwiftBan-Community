# 日志格式测试夹具

此目录中的访问日志均为自编测试数据，不复制生产日志或外部项目的日志内容。客户端地址使用文档专用 IPv4/IPv6 地址，主机名使用 `.test` 示例域名。

每个 `.log` 文件保存一种格式的原始行，配套 `.expected` 文件按行保存预期的标准化字段，字段顺序为：

`epoch|IP|status|method|host|URI|user-agent|referer`

样例时间固定在 2026-11-21 11:59 UTC。`detection-candidates.expected` 和 `detection-watch.expected` 是混合格式样例的聚合检测契约，分别按 TSV 列出预期封禁候选及 WATCH 结果。新增或修改样例时，同时更新对应字段黄金结果和检测契约，并运行 `bash tests/test_log_fixtures.sh`。

检测契约字段：封禁候选为 `IP、原因、计数、阈值`；WATCH 为 `IP、规则、计数、阈值、窗口秒、接口`。安全负例中的伪造 IP 只出现在 URI、UA 或 Referer，预期客户端 IP 必须仍来自原始日志规定的来源地址字段。不要把样例中的攻击路径、UA 或地址改成真实用户数据。
