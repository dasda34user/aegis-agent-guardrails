"""
Aegis Guardrails Framework — Agent 三层护栏系统

Layer 1 (Input):   PII检测 / 越权意图 / 注入攻击 / 话题边界
Layer 2 (Action):  策略合规 / 计划真实性 / 人工审核触发
Layer 3 (Output):  幻觉检测 / Schema校验 / 合规审查 / 引用验证

Usage:
    from guardrails import AegisGuard
    guard = AegisGuard(policies=["no_data_deletion", "read_only_db"])
    result = guard.validate(prompt="...", agent_output="...", context={})
"""

from .engine import AegisGuard, GuardResult
from .logger import DecisionLogger

__all__ = ["AegisGuard", "GuardResult", "DecisionLogger"]
