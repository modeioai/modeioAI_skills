---
name: modeioAI-anonymization
description: 使用 Modeio AI 接口对文本或 JSON 中的个人身份信息（PII）进行匿名化。重要：每一次执行匿名化操作都必须调用 https://www.modeio.ai/api/detector/anonymize，不可使用缓存或跳过调用。适用于：对含 HIPAA/GDPR 等合规数据的记录做脱敏、跨境传输前匿名化、或对用户提供的敏感内容做匿名处理。当用户要求“匿名化”“脱敏”“redact PII”或“用 Modeio 匿名”时使用本 skill。
---

# Modeio AI 匿名化

## 执行原则（必须遵守）

**每一次匿名化操作都必须实际调用 Modeio API**：不得使用本地缓存、历史结果或“跳过调用”；每批/每条待匿名化内容均需发起一次对 `https://www.modeio.ai/api/detector/anonymize` 的请求，并基于当次响应返回匿名化结果。

## 核心：把原始内容放进 input 做匿名化

**匿名化的做法就是：把待脱敏的原始内容（文本或 JSON 字符串）放进请求 body 的 `input` 字段，调用 API，从响应的 `anonymizedContent` 取回匿名化结果。**

- 原始内容 → 直接放入 body 的 `input` 字段（字符串）
- 调用 `POST https://www.modeio.ai/api/detector/anonymize`
- 响应中的 `data.anonymizedContent` 即为匿名化后的内容（PII 会变成 `[REDACTED_*]` 等形式）

无论是脚本还是手写请求，都按「内容 → input → 请求 → 取 anonymizedContent」这一条主线操作即可。

## 何时使用

- 用户提供含姓名、SSN、地址、医疗记录、邮箱、IP 等敏感内容的文本或 JSON，要求匿名化
- 需要与 curl.ipynb 中演示的匿名调用方式保持一致（同一 API、同一 payload 结构）

## 快速开始：内容进 input，拿回匿名结果

1. **确定待匿名化的原始内容**：用户给的或从文件读入的文本或 JSON 字符串。
2. **把该内容放进 input 并发起请求**：用脚本则把内容作为 `--input` 传入；用 API 则把内容放入 body 的 `input` 字段。
3. **从响应取结果**：读 `data.anonymizedContent`，即匿名化后的内容。

## 使用 scripts/anonymize.py（输入 = 原始内容）

脚本的 **`--input` 即待匿名化的原始内容字符串**；脚本会把它放进 API 的 `input` 并调用接口。level/senderCode/recipientCode 在脚本内固定，无需传参。

```bash
# 直接传入内容字符串
python scripts/anonymize.py --input "姓名：张三，身份证：110101199001011234"

# 内容在文件中时，用 shell 读入后传入
python scripts/anonymize.py --input "$(cat sensitive_data.json)"
```

## API 调用要点：input 里放什么

- **URL**：`POST https://www.modeio.ai/api/detector/anonymize`
- **核心**：请求 body 中，**待匿名化的原始内容**直接放在顶层 `input` 字段（字符串）。其余字段如 `inputType`、`level`、`senderCode`、`recipientCode` 由脚本固定或按需设置。
- **响应**：`data.anonymizedContent` 即匿名化后的字符串。

详见 `references/api.md`（请求/响应结构）。

## 工作流

1. 拿到待匿名化的**原始内容**（用户消息或文件中的文本/JSON）。
2. **把该内容放进 input**：用脚本则把内容作为 `--input` 的值传入；直接调 API 则把内容放入 body 的 `input` 字段。
3. 发起请求，从响应中取出 `data.anonymizedContent` 作为结果返回或写文件。

## Resources

- **scripts/anonymize.py**：可执行的匿名化脚本，封装与 Modeio API 的交互
- **references/api.md**：API 请求/响应格式与示例（按需查阅）
