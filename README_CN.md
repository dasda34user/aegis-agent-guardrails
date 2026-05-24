# Aegis 护栏系统 — 学习指南

## 项目概述

Agent 三层护栏校验系统。Input/Action/Output 全流程 + 正则+LLM 双层语义分析。

## 核心概念

### 1. 为什么需要护栏

Agent 的第一目标是"完成任务"，不是"保证安全"。护栏 = 独立的安全防线。

### 2. 三层架构

```
Layer 1 (Input):   正则 (PII/意图/注入, <1ms) → LLM 语义确认
Layer 2 (Action):  Policy-as-Code (YAML 策略 → LLM 生成代码 → 动态执行)
Layer 3 (Output):  正则 (有害/越权) → LLM 幻觉检测 (逐句事实核查)
```

### 3. 正则+LLM 双层

```
正则: 速度快 (<1ms), 但只能匹配关键词
LLM:  理解语义 ("清理" = delete), 但慢 (200ms+)
组合: 正则快速过滤 → 正则漏掉的交给 LLM
```

对抗测试结果: 正则漏 5/5 → LLM 捕获 5/5 (100% 补救率)

### 4. Policy-as-Code

```python
# 传统: 硬编码策略
forbidden = ["DELETE", "DROP"]

# Policy-as-Code: YAML 策略 → LLM 生成代码 → 动态 exec()
policy = "Agent 只能对数据库执行只读操作"
code = llm.generate_validator(policy)
exec(code)  # 动态执行生成的校验函数
```

### 5. DecisionLogger

每条交互记录完整的决策轨迹 (JSONL):
`trace_id → 用户输入 → L1结果 → L2结果 → L3结果 → 最终判定 → 耗时`

## 文件结构

| 文件 | 作用 |
|------|------|
| `guardrails/engine.py` | 三层护栏引擎 + AegisGuard |
| `guardrails/deep_engine.py` | LLM 语义分析 + 幻觉检测 |
| `guardrails/policy_engine.py` | Policy-as-Code 策略引擎 |
| `guardrails/adversarial.py` | 对抗测试生成器 |
| `guardrails/logger.py` | 决策日志 (JSONL) |
| `tests/test_boundary_cases.py` | 19 项边界测试 |
| `tests/test_adversarial.py` | 深度对抗测试 |

## 启动

```bash
uv run python tests/test_boundary_cases.py   # 基础测试
uv run python tests/test_adversarial.py       # 深度对抗测试
```
