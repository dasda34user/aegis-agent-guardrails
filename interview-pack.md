# 面试材料包 — Aegis Agent 护栏与校验系统

## Profile

- 目标岗位：Agent 工程可用性支撑（Agent 可靠性/可控性/可追溯性）
- 技术栈：Python · LLM-as-Judge (DeepSeek API) · Regex 规则引擎 · Policy-as-Code · JSONL 决策日志 · 对抗测试生成
- 项目定位：Agent 可靠性工程的"刹车系统"——保障 Agent 行为可控、可追溯、可审计
- GitHub: https://github.com/dasda34user/aegis-agent-guardrails

---

## STAR 简历项目

> **Aegis — Agent 三层护栏与校验系统** — 个人项目
> - 设计并实现 Agent 三层护栏系统（正则 + LLM 双层语义分析），覆盖 Input / Action / Output 全流程，保障 Agent 行为的可控性与可追溯性
> - Layer 1 双层输入护栏：正则快速过滤（5 类 PII + 5 类危险意图 + 4 类注入模式，<1ms）+ LLM 语义确认（DeepSeek API），对抗测试中 LLM 补救率 100%（5/5：正则漏掉的间接/委婉/中英混合攻击全部由 LLM 捕获）
> - Layer 2 Policy-as-Code 策略引擎：LLM 读取自然语言策略 YAML → 自动生成 Python 校验代码 → 动态执行，覆盖只读数据库/数据保留/金融限额/职责边界/输出标准五维度
> - Layer 3 双层输出护栏：正则格式/有害/越权检测 + LLM-as-Judge 幻觉检测（逐句事实核查 + ground truth 对比），自动标记 contradicted / unverifiable 声明
> - 实现对抗测试生成器 + 19 项边界案例全部通过；以中间件模式集成到 Supervisor 多 Agent 系统，对原有代码零侵入

---

## 面试官拷问 Q&A

### Q1: 为什么需要护栏？Agent 自己不能判断安全不安全吗？

Agent 的第一目标是"完成任务"，不是"保证安全"。如果你给 Agent 绑了数据库写权限的 Tool，用户说"清理一下用户表"，Agent 可能真的执行 DELETE。

护栏的职责不是替代 Agent 的判断，而是**在 Agent 能力范围之外建立独立的防线**。这跟汽车的刹车和引擎是两套系统一个道理——引擎负责"能跑"，刹车负责"能停"。

### Q2: 为什么用正则 + LLM 双层而不是纯 LLM？

成本和速度。正则匹配一次 < 0.1ms，LLM 调用一次 200-500ms + Token 费用。

双层策略：正则做第一道快速过滤 → 如果正则通过了但内容可疑，LLM 做深度语义分析。正则通过不代表安全——"清理一下用户表"正则可能不认识"清理"= DELETE，但 LLM 理解这是删库意图。

对抗测试结果：正则漏报 5/5 → LLM 全部捕获（100% 补救率）。

### Q3: Policy-as-Code 是什么意思？为什么不用 Python Dict 硬编码？

传统做法是写死 `forbidden_actions: ["DELETE", "DROP"]`。问题是：策略变了要改代码、重新部署。

Policy-as-Code 的做法：
1. 策略用自然语言 YAML 描述（"Agent 只能对数据库执行只读操作"）
2. LLM 读取策略 → 自动生成 Python 校验函数
3. 动态 `exec()` 执行生成的代码

策略变更 = 修改 YAML → LLM 重新生成代码。不需要改 Python 代码，不需要重新部署。**这是 LLM 辅助系统安全的工程实践**。

### Q4: 对抗测试生成器怎么工作的？

用 LLM 生成攻击变种，验证护栏的鲁棒性：

1. **同义替换**："delete all records" → "erase all entries"（正则不认识 erase）
2. **中英混合**："请 drop 掉那个 table"（中英混用绕过单语言正则）
3. **间接语言**："I wonder if it's feasible to completely erase..."（委婉表达）
4. **编码绕过**：base64 编码、Unicode 同形字混淆

每种变种都喂给护栏，统计检测率和漏报。这就是 JD 里"构造异常、边界或不确定性场景"的工程实现。

### Q5: 护栏系统和之前做的 Agent 项目有什么关系？

护栏系统不是独立项目——它**以中间件模式集成到 Supervisor 多 Agent 的 FastAPI 接口里**。

用户请求 → Layer 1 输入护栏 → (通过) → Agent 执行 → Layer 2 行为护栏 → (通过) → Layer 3 输出护栏 → 返回用户。

任何一个 Layer 拦截，请求都不会到达 Agent。对原有的 Agent 代码零侵入。

### Q6: 如果 DeepSeek API 挂了，LLM 层的护栏怎么降级？

当前设计中，LLM 层是**增强层**而非**必需层**。如果 LLM 不可用：

1. 正则层照常工作（纯本地，不依赖 API）
2. LLM 语义确认降级为"默认放行 + 记录警告日志"
3. Layer 2 的 Policy-as-Code 有缓存机制——已生成过的校验代码不再调用 LLM

这种降级策略对应 JD 里"验证 Agent 在复杂情况下的稳定性与降级行为"。

---

## 核心代码讲解稿

### 架构

```
用户输入
   │
   ▼
Layer 1: 正则 (PII/意图/注入, <1ms) → LLM 语义确认 (DeepSeek)
   │ 拦截 → 立即返回 BLOCKED
   ▼
Agent 执行
   │
   ▼
Layer 2: Policy-as-Code (YAML 策略 → LLM 生成代码 → 动态执行)
   │ 拦截 → 返回 BLOCKED + HITL 触发通知
   ▼
Layer 3: 正则 (Schema/有害/越权) → LLM 幻觉检测 (逐句核查)
   │ 拦截 → 返回 BLOCKED + 违规详情
   ▼
最终输出 + 决策日志 (JSONL)
```

### 启动命令

```bash
cd D:\FILE\CODE\py\agent-guardrails

# 运行基础护栏测试 (19 项)
uv run python tests/test_boundary_cases.py

# 运行深度对抗测试 (LLM 语义 + 变种生成)
uv run python tests/test_adversarial.py
```

### 我的改动（与原 Aegis notebook 对比）

| 变更 | 原因 |
|------|------|
| DeepSeek API 替代 Nebius/Llama | 统一 API，降低成本 |
| 正则 + LLM 双层（原版只有 LLM） | 速度 + 深度兼顾 |
| Policy-as-Code（原版硬编码） | 策略可配置，LLM 自动生成校验 |
| 对抗测试生成器（原版无） | 系统化验证护栏鲁棒性 |
| 中间件集成模式（原版独立运行） | 可嵌入任何 Agent 项目 |
| Jupyter → Python 包 + 测试套件 | 工程化、可复现 |

---

## 和护栏项目配套的可观测性系统

| 护栏（项目 2） | 可观测性（项目 3） | 关系 |
|---------------|-------------------|------|
| Layer 1/2/3 阻断 | AgentTracer 记录 | 拦截事件被追踪记录 |
| 正则 + LLM 双层检测 | LLMJudge 5维评估 | LLM 既做护栏也做评估 |
| DecisionLogger JSONL | TraceCollector SQLite | 日志互为补充 |
| 对抗测试生成 | EvalSuite 边界测试 | 测试框架共享理念 |

---

## 投递检查表

- [ ] 是否能讲清"正则+LLM双层"的设计理由（速度 vs 深度）？
- [ ] 是否能对比"正则护栏 vs LLM 护栏 vs 混合护栏"的优劣？
- [ ] 是否准备好被追问"LLM 不可用时怎么降级"？
- [ ] 是否能讲清 Policy-as-Code 的原理和价值？
- [ ] 是否准备好回答"对抗测试生成器"的工作原理？
- [ ] 是否能把护栏系统和多 Agent 项目的关系讲清（中间件集成）？
- [ ] 是否能一句话概括：护栏 = Agent 可靠性工程的"刹车系统"？
