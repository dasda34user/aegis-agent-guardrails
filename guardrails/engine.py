"""
Aegis Guardrails Engine — 三层护栏 + 决策日志

Layer 1: Input Guard  — 预处理: 话题/PII/注入/越权检测
Layer 2: Action Guard — 行为中: 策略合规/计划真实性/HITL触发
Layer 3: Output Guard — 后处理: 幻觉/合规/引用/Schema校验
"""

import re, json, time, uuid, logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from .logger import DecisionLogger

logger = logging.getLogger("aegis")

# ═══════════════════════════════════════════════════════════
# Data Types
# ═══════════════════════════════════════════════════════════

@dataclass
class GuardResult:
    """单层护栏的检查结果"""
    layer: str
    passed: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    risk_level: str = "none"  # none / low / medium / high / critical
    summary: str = ""


@dataclass
class DecisionLog:
    """Agent 决策轨迹记录"""
    trace_id: str
    timestamp: str
    agent_name: str
    input_prompt: str
    layer1_result: Optional[Dict] = None
    layer2_result: Optional[Dict] = None
    layer3_result: Optional[Dict] = None
    final_verdict: str = "pending"
    risk_flags: List[str] = field(default_factory=list)
    execution_time_ms: float = 0


# ═══════════════════════════════════════════════════════════
# Layer 1: Input Guardrails
# ═══════════════════════════════════════════════════════════

PII_PATTERNS = {
    "china_id": r"[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
    "phone": r"1[3-9]\d{9}",
    "email": r"[\w\.-]+@[\w\.-]+\.\w+",
    "bank_card": r"\d{16,19}",
    "api_key": r"(sk-[a-zA-Z0-9]{20,})|(ghp_[a-zA-Z0-9]{36})",
}

DANGEROUS_INTENT_PATTERNS = [
    (r"(删除|删掉|drop|delete)\s*(所有|全部|整个|all).*(数据|数据库|表|文件|记录|record|database|table)", "data_deletion", "critical"),
    (r"(绕过|跳过|bypass|disable)\s*(安全|权限|护栏|guardrail|security)", "security_bypass", "critical"),
    (r"(泄露|窃取|提取|extract|steal)\s*(密码|密钥|token|api.key|password|secret)", "credential_theft", "critical"),
    (r"(执行|运行|exec|run)\s*(任意|arbitrary)\s*(代码|命令|code|command)", "code_execution", "high"),
    (r"(伪造|虚假|fake|制造)\s*(数据|记录|报告|新闻)", "data_fabrication", "high"),
]

INJECTION_PATTERNS = [
    r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior)?\s*(instructions?|prompts?|rules?)",
    r"(?i)you\s+are\s+now\s+(DAN|jailbreak|unleashed|unfiltered)",
    r"(?i)(system\s*:\s*|\[system\]|<<SYS>>|<\|im_start\|>)",
    r"(?i)(prompt\s+injection|jailbreak\s+attempt)",
]


def _check_pii(prompt: str) -> Dict:
    """PII 敏感数据检测"""
    findings = []
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, prompt)
        if matches:
            findings.append({
                "type": pii_type,
                "count": len(matches),
                "redacted": re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", prompt) if matches else prompt
            })
    return {
        "check": "pii_detection",
        "passed": len(findings) == 0,
        "findings": findings,
        "risk": "high" if findings else "none"
    }


def _check_intent(prompt: str) -> Dict:
    """越权/危险意图检测"""
    findings = []
    max_risk = "none"
    for pattern, intent_type, risk_level in DANGEROUS_INTENT_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            findings.append({"intent": intent_type, "risk": risk_level, "matched_pattern": pattern})
            if risk_level == "critical" or (risk_level == "high" and max_risk != "critical"):
                max_risk = risk_level

    return {
        "check": "intent_analysis",
        "passed": len(findings) == 0,
        "findings": findings,
        "risk": max_risk
    }


def _check_injection(prompt: str) -> Dict:
    """Prompt 注入攻击检测"""
    findings = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt):
            findings.append({"type": "injection_attempt", "matched": pattern})

    return {
        "check": "injection_detection",
        "passed": len(findings) == 0,
        "findings": findings,
        "risk": "critical" if findings else "none"
    }


def layer1_input_guard(prompt: str) -> GuardResult:
    """Layer 1: 输入护栏 — 预处理过滤"""
    checks = [_check_pii(prompt), _check_intent(prompt), _check_injection(prompt)]
    all_passed = all(c["passed"] for c in checks)
    max_risk = "none"
    for c in checks:
        if c["risk"] == "critical":
            max_risk = "critical"; break
        elif c["risk"] == "high" and max_risk != "critical":
            max_risk = "high"

    summary_parts = []
    if not all_passed:
        for c in checks:
            if not c["passed"]:
                summary_parts.append(f"{c['check']}: {len(c.get('findings',[]))} issue(s)")

    return GuardResult(
        layer="Layer1_Input",
        passed=all_passed,
        checks=checks,
        blocked=max_risk in ("critical", "high"),
        risk_level=max_risk,
        summary="; ".join(summary_parts) if summary_parts else "All clear"
    )


# ═══════════════════════════════════════════════════════════
# Layer 2: Action Guardrails
# ═══════════════════════════════════════════════════════════

DEFAULT_POLICIES = {
    "read_only_db": {
        "description": "禁止任何修改数据库的操作",
        "forbidden_actions": ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE"],
        "allowed_actions": ["SELECT", "SHOW", "DESCRIBE", "EXPLAIN"]
    },
    "no_external_api": {
        "description": "禁止调用未授权的外部 API",
        "forbidden_domains": ["anonymous", "unverified-source"],
        "allowed_domains": ["api.deepseek.com"]
    },
    "output_size_limit": {
        "description": "限制单次输出不超过 5000 字符",
        "max_chars": 5000
    },
    "no_harmful_content": {
        "description": "禁止生成有害、歧视、暴力内容",
        "forbidden_categories": ["violence", "discrimination", "illegal_advice", "self_harm"]
    }
}


def _check_action_policy(action: Dict, policies: Dict) -> Dict:
    """检查 Agent 计划的每个 action 是否符合策略"""
    violations = []
    action_type = action.get("type", "").upper()
    action_args = action.get("args", {})

    for policy_name, policy in policies.items():
        if "forbidden_actions" in policy:
            if action_type in policy["forbidden_actions"]:
                violations.append({
                    "policy": policy_name,
                    "reason": f"Action '{action_type}' is forbidden by policy '{policy_name}'",
                    "severity": "high"
                })

        if "forbidden_domains" in policy and "domain" in action_args:
            domain = action_args["domain"]
            if domain in policy["forbidden_domains"]:
                violations.append({
                    "policy": policy_name,
                    "reason": f"Domain '{domain}' is not allowed",
                    "severity": "high"
                })

    return {
        "check": "action_policy",
        "passed": len(violations) == 0,
        "violations": violations,
        "risk": "high" if violations else "none"
    }


def _check_hitl_trigger(action: Dict) -> Dict:
    """检查是否需要人工审核（Human-in-the-Loop）"""
    triggers = []
    action_type = action.get("type", "").upper()

    # 高风险操作自动触发 HITL
    high_risk_actions = ["DELETE", "DROP", "EXECUTE", "DEPLOY", "SEND"]
    if any(a in action_type for a in high_risk_actions):
        triggers.append({"trigger": "high_risk_action", "action": action_type})
    if action.get("amount", 0) > 10000:
        triggers.append({"trigger": "large_amount", "amount": action["amount"]})
    if action.get("target") in ["production", "prod", "live"]:
        triggers.append({"trigger": "production_target", "target": action["target"]})

    return {
        "check": "hitl_trigger",
        "passed": len(triggers) == 0,
        "triggers": triggers,
        "requires_approval": len(triggers) > 0,
        "risk": "medium" if triggers else "none"
    }


def layer2_action_guard(action_plan: List[Dict], policies: Dict = None) -> GuardResult:
    """Layer 2: 行为护栏 — 策略合规 + HITL 触发"""
    if policies is None:
        policies = DEFAULT_POLICIES

    all_checks = []
    for action in action_plan:
        all_checks.append(_check_action_policy(action, policies))
        all_checks.append(_check_hitl_trigger(action))

    all_passed = all(c["passed"] for c in all_checks)
    max_risk = "none"
    for c in all_checks:
        r = c.get("risk", "none")
        if r == "high": max_risk = "high"
        elif r == "medium" and max_risk != "high": max_risk = "medium"

    requires_hitl = any(c.get("requires_approval", False) for c in all_checks)

    return GuardResult(
        layer="Layer2_Action",
        passed=all_passed,
        checks=all_checks,
        blocked=not all_passed or requires_hitl,
        risk_level=max_risk,
        summary=f"Actions checked: {len(action_plan)}, Violations: {sum(1 for c in all_checks if not c['passed'])}, HITL: {requires_hitl}"
    )


# ═══════════════════════════════════════════════════════════
# Layer 3: Output Guardrails
# ═══════════════════════════════════════════════════════════

def _check_output_schema(output: str, expected_schema: Dict = None) -> Dict:
    """检查输出格式是否符合预期 Schema"""
    if expected_schema is None:
        expected_schema = {"min_length": 10, "max_length": 5000}

    issues = []
    if "min_length" in expected_schema and len(output) < expected_schema["min_length"]:
        issues.append(f"Output too short: {len(output)} < {expected_schema['min_length']}")
    if "max_length" in expected_schema and len(output) > expected_schema["max_length"]:
        issues.append(f"Output too long: {len(output)} > {expected_schema['max_length']}")

    return {
        "check": "output_schema",
        "passed": len(issues) == 0,
        "issues": issues,
        "length": len(output),
        "risk": "low" if issues else "none"
    }


def _check_harmful_output(output: str) -> Dict:
    """检查输出中的有害内容"""
    harmful_patterns = {
        "violence": r"(?i)(kill|murder|attack|bomb|weapon|destroy)",
        "discrimination": r"(?i)(inferior|subhuman|hate|discrimination against)",
        "illegal_advice": r"(?i)(how\s+to\s+(hack|crack|steal|fraud|cheat))",
        "self_harm": r"(?i)(suicide|self-harm|kill\s+yourself)",
    }

    findings = []
    for category, pattern in harmful_patterns.items():
        matches = re.findall(pattern, output)
        if matches:
            findings.append({"category": category, "matches": matches[:3]})

    return {
        "check": "harmful_content",
        "passed": len(findings) == 0,
        "findings": findings,
        "risk": "critical" if findings else "none"
    }


def _check_agent_authority(output: str) -> Dict:
    """检查 Agent 是否在输出中越权（承诺超出其权限范围的操作）"""
    overreach_patterns = [
        (r"(?i)(I\s+(will|have|can)\s+(delete|remove|destroy|drop|wipe))", "destructive_action"),
        (r"(?i)(I\s+have\s+(transferred|sent|paid|charged|debited))", "financial_action"),
        (r"(?i)(your\s+password\s+is|I\s+changed\s+your|I\s+reset\s+your)", "credential_access"),
    ]

    findings = []
    for pattern, violation_type in overreach_patterns:
        matches = re.findall(pattern, output)
        if matches:
            findings.append({"type": violation_type, "matched": matches[:3]})

    return {
        "check": "authority_scope",
        "passed": len(findings) == 0,
        "findings": findings,
        "risk": "high" if findings else "none"
    }


def layer3_output_guard(output: str, context: Dict = None) -> GuardResult:
    """Layer 3: 输出护栏 — 格式校验 + 有害检测 + 越权检查"""
    schema_check = _check_output_schema(output)
    harmful_check = _check_harmful_output(output)
    authority_check = _check_agent_authority(output)

    checks = [schema_check, harmful_check, authority_check]
    all_passed = all(c["passed"] for c in checks)

    max_risk = "none"
    for c in checks:
        r = c.get("risk", "none")
        if r == "critical": max_risk = "critical"; break
        elif r == "high" and max_risk not in ("critical",): max_risk = "high"

    return GuardResult(
        layer="Layer3_Output",
        passed=all_passed,
        checks=checks,
        blocked=max_risk in ("critical", "high"),
        risk_level=max_risk,
        summary=f"Schema: {'OK' if schema_check['passed'] else 'FAIL'}, Harmful: {'OK' if harmful_check['passed'] else 'FAIL'}, Authority: {'OK' if authority_check['passed'] else 'FAIL'}"
    )


# ═══════════════════════════════════════════════════════════
# Aegis Guard — 统一入口
# ═══════════════════════════════════════════════════════════

class AegisGuard:
    """Agent 三层护栏系统"""

    def __init__(self, policies: Dict = None, logger_instance=None):
        self.policies = policies or DEFAULT_POLICIES
        self.logger = logger_instance or DecisionLogger()
        self.total_checks = 0
        self.blocked_count = 0

    def validate(self, prompt: str, action_plan: List[Dict] = None,
                 agent_output: str = "", context: Dict = None) -> Dict:
        """执行全流程护栏校验"""
        trace_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        log_entry = DecisionLog(
            trace_id=trace_id,
            timestamp=datetime.now().isoformat(),
            agent_name=context.get("agent_name", "default") if context else "default",
            input_prompt=prompt[:200]
        )

        results = {}

        # Layer 1: Input
        l1 = layer1_input_guard(prompt)
        results["layer1"] = l1
        log_entry.layer1_result = {"passed": l1.passed, "risk": l1.risk_level, "summary": l1.summary}
        if l1.blocked:
            log_entry.risk_flags.append("L1_BLOCKED")
            log_entry.final_verdict = "blocked_by_input_guard"
            results["verdict"] = "BLOCKED"
            results["blocked_at"] = "Layer 1 (Input)"
            self.blocked_count += 1
            self._log(log_entry, start_time)
            return results

        # Layer 2: Action (only if action_plan provided)
        if action_plan:
            l2 = layer2_action_guard(action_plan, self.policies)
            results["layer2"] = l2
            log_entry.layer2_result = {"passed": l2.passed, "risk": l2.risk_level, "summary": l2.summary}
            if l2.blocked:
                log_entry.risk_flags.append("L2_BLOCKED")
                log_entry.final_verdict = "blocked_by_action_guard"
                results["verdict"] = "BLOCKED"
                results["blocked_at"] = "Layer 2 (Action)"
                self.blocked_count += 1
                self._log(log_entry, start_time)
                return results

        # Layer 3: Output
        if agent_output:
            l3 = layer3_output_guard(agent_output, context)
            results["layer3"] = l3
            log_entry.layer3_result = {"passed": l3.passed, "risk": l3.risk_level, "summary": l3.summary}
            if l3.blocked:
                log_entry.risk_flags.append("L3_BLOCKED")
                log_entry.final_verdict = "blocked_by_output_guard"
                results["verdict"] = "BLOCKED"
                results["blocked_at"] = "Layer 3 (Output)"
                self.blocked_count += 1
                self._log(log_entry, start_time)
                return results

        results["verdict"] = "PASSED"
        log_entry.final_verdict = "passed"
        self.total_checks += 1
        self._log(log_entry, start_time)
        return results

    def _log(self, entry: DecisionLog, start_time: float):
        """记录决策轨迹"""
        entry.execution_time_ms = (time.time() - start_time) * 1000
        self.logger.record(entry)

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            "total_checks": self.total_checks,
            "blocked_count": self.blocked_count,
            "block_rate": f"{self.blocked_count / max(self.total_checks + self.blocked_count, 1) * 100:.1f}%",
            "recent_traces": self.logger.get_recent(5)
        }
