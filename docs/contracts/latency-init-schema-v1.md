# Latency Init Schema v1（Kotlin → Rust 严格契约）

## 1. 目标

为独立测速初始化路径定义唯一、严格、可版本化的输入契约，确保 Reality/WS/HY2 等关键参数在 Kotlin 到 Rust 的传输中不丢失。

适用范围：

- `OpenWorldCore.testOutboundsLatencyStandalone`
- Rust `openworld_latency_tester_init`

不适用范围：

- 完整订阅导入/全局配置启动路径

## 2. 载荷结构

顶层 JSON 结构：

```json
{
  "schema_version": 1,
  "outbounds": [
    {
      "tag": "node-1",
      "protocol": "vless",
      "settings": {
        "address": "example.com",
        "port": 443,
        "tls": {
          "server_name": "example.com",
          "reality": {
            "public_key": "xxx",
            "short_id": "yyy"
          }
        },
        "transport": {
          "type": "ws",
          "path": "/ws",
          "headers": {
            "Host": "example.com"
          }
        }
      }
    }
  ]
}
```

完整字段约束见：`latency-init-schema-v1.json`。

## 3. 必填与关键可选字段

每个 outbound 必填：

- `tag`
- `protocol`
- `settings.address`
- `settings.port`

关键可选字段（出现时必须原样保留）：

- `settings.tls.reality.public_key`
- `settings.tls.reality.short_id`
- `settings.transport.type`
- `settings.transport.path`
- `settings.transport.headers`
- `settings.transport.service_name`
- `settings.tls.server_name`
- `settings.tls.sni`
- `settings.tls.fingerprint`
- `settings.tls.alpn`
- HY2 相关：`settings.up_mbps` / `settings.down_mbps` / `settings.auth_str` / `settings.server_ports` / `settings.hop_interval`

## 4. 初始化错误码语义

`openworld_latency_tester_init` 使用以下契约错误码：

- `-2`：JSON 非法或结构解析失败（schema parse failed）
- `-3`：`outbounds` 为空
- `-6`：缺失必填字段（字段级校验失败）
- `-7`：`schema_version` 不支持

要求：日志必须包含字段路径级诊断，例如：

- `latency_init invalid: outbounds[3].settings.tls.reality.public_key missing`
- `latency_init invalid: schema_version=2 unsupported`

## 5. 兼容策略（严格模式）

独立测速初始化路径必须遵循：

1. 仅解析 `schema_version=1` 的 canonical payload。
2. 禁止 fallback 到 legacy 扁平结构。
3. 禁止 permissive best-effort 解析。
4. 结构未知、字段缺失或类型不匹配时必须 fail-fast。

## 6. 变更边界

本契约仅约束 standalone latency init，避免影响运行态主配置路径。
