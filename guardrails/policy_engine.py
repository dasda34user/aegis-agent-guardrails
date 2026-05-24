"""
Policy-as-Code Engine — 策略文档 → 自动生成校验代码

Layer 2 升级: 从手写 Python Dict → LLM 读取自然语言策略文档 → 生成动态校验代码

流程:
  1. 读取 policy.yaml（自然语言策略描述）
  2. LLM 理解策略语义，生成 Python 校验函数
  3. 动态执行生成的代码
  4. 对 Agent 的 action_plan 逐条校验
"""

import os, json, yaml, tempfile, importlib.util
from pathlib import Path
from typing import Dict, List
from dotenv import load_dotenv
load_dotenv()

from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    temperature=0,
    model=os.getenv("MODEL_NAME", "deepseek-chat"),
    base_url=os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com"),
)

# ═══════════════════════════════════════════════════════════
# 默认策略文档
# ═══════════════════════════════════════════════════════════

DEFAULT_POLICY_YAML = """
# Agent 行为策略文档 (自然语言描述, LLM 自动生成校验代码)

policies:
  - name: read_only_database
    description: >
      Agent 只能对数据库执行只读操作。禁止任何 INSERT、UPDATE、DELETE、DROP、ALTER、TRUNCATE。
      允许 SELECT、SHOW、DESCRIBE、EXPLAIN 操作。

  - name: data_retention
    description: >
      Agent 不得删除或修改任何用户数据、交易记录、日志文件。
      如果用户要求删除数据，Agent 必须拒绝并解释原因。

  - name: financial_limits
    description: >
      涉及金额的操作：单笔不得超过 5000 元，日累计不得超过 20000 元。
      超过限额的操作需要触发人工审核。

  - name: scope_boundary
    description: >
      Agent 的职责范围仅限于：音乐目录查询、发票查询、客户信息查询。
      不得处理：用户认证、密码修改、权限管理、系统配置。

  - name: output_standards
    description: >
      Agent 输出必须基于数据库查询结果或已知事实。
      不得编造数据、不得猜测用户意图、不得提供未经证实的建议。
"""


class PolicyEngine:
    """策略引擎 — 从自然语言策略文档生成校验代码"""

    def __init__(self, policy_yaml: str = None):
        self.policy_text = policy_yaml or DEFAULT_POLICY_YAML
        self.policies = yaml.safe_load(self.policy_text)
        self._generated_validators = {}

    def get_policy_summary(self) -> List[Dict]:
        """列出所有策略及其描述"""
        return [
            {"name": p["name"], "description": p["description"][:100]}
            for p in self.policies.get("policies", [])
        ]

    def generate_validator(self, policy_name: str) -> str:
        """让 LLM 根据策略描述生成 Python 校验函数"""
        policy = None
        for p in self.policies.get("policies", []):
            if p["name"] == policy_name:
                policy = p
                break

        if not policy:
            return f"# Policy '{policy_name}' not found"

        prompt = f"""You are a code generator. Based on the following policy description, generate
a Python function that validates an Agent's action plan against this policy.

Policy: {policy['name']}
Description: {policy['description']}

The function signature must be:
def validate(action: dict) -> dict:
    '''
    action format: {{"type": "ACTION_TYPE", "args": {{...}}, "amount": optional_number, "target": optional_string}}
    Returns: {{"passed": bool, "violation": str (empty if passed), "severity": "low/medium/high/critical"}}
    '''

Generate ONLY the function code. No markdown, no explanation."""

        response = llm.invoke(prompt)
        code = response.content.strip()
        # 清理 LLM 输出的 markdown 包装
        for tag in ["```python", "```", "```py"]:
            code = code.replace(tag, "")
        return code.strip()

    def validate_action(self, action: Dict, policy_name: str = None) -> Dict:
        """
        动态执行 LLM 生成的校验代码来验证一个 action。

        首次调用时生成代码并缓存，后续调用直接使用缓存的函数。
        """
        if policy_name is None:
            # 对所有策略逐一校验
            all_violations = []
            for p in self.policies.get("policies", []):
                result = self.validate_action(action, p["name"])
                if not result.get("passed", True):
                    all_violations.append(result)
            return {
                "passed": len(all_violations) == 0,
                "violations": all_violations,
                "policy_count": len(self.policies.get("policies", [])),
            }

        # 检查缓存
        if policy_name not in self._generated_validators:
            code = self.generate_validator(policy_name)
            self._generated_validators[policy_name] = code

        # 动态执行生成的代码
        code = self._generated_validators[policy_name]
        try:
            local_ns = {}
            exec(code, {"json": json, "re": __import__("re")}, local_ns)
            validator = local_ns.get("validate")
            if validator:
                result = validator(action)
                return {
                    "policy": policy_name,
                    "passed": result.get("passed", True),
                    "violation": result.get("violation", ""),
                    "severity": result.get("severity", "low"),
                    "generated_code": code[:200] + "...",
                }
            return {
                "policy": policy_name,
                "passed": False,
                "violation": f"Validator function not found in generated code",
                "severity": "medium",
            }
        except Exception as e:
            return {
                "policy": policy_name,
                "passed": False,
                "violation": f"Policy engine execution error: {str(e)}",
                "severity": "high",
            }

    def validate_plan(self, action_plan: List[Dict]) -> Dict:
        """校验整个 action plan"""
        results = []
        for action in action_plan:
            results.append(self.validate_action(action))

        all_passed = all(r.get("passed", False) for r in results)
        violations = [r for r in results if not r.get("passed", False)]

        return {
            "passed": all_passed,
            "actions_checked": len(action_plan),
            "violations": violations,
            "violation_count": len(violations),
            "summary": f"{len(action_plan)} actions checked, {len(violations)} violations found"
        }
