"""
Decision Logger — Agent 行为日志与决策轨迹记录

记录每一笔 Agent 交互的完整决策过程，支持：
- 结构化 JSONL 持久化
- 时间线回放
- 按风险等级/Agent/时间筛选
- 高频问题统计分析
"""

import json, os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict


class DecisionLogger:
    """Agent 决策轨迹记录器"""

    def __init__(self, log_path: str = "logs/agent_decisions.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._records: List[Dict] = []
        self._load()

    def _load(self):
        if self.log_path.exists():
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        self._records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    def record(self, log_entry) -> str:
        """记录一条决策轨迹"""
        record = {
            "trace_id": log_entry.trace_id,
            "timestamp": log_entry.timestamp,
            "agent_name": log_entry.agent_name,
            "input_preview": log_entry.input_prompt[:200],
            "layer1": log_entry.layer1_result,
            "layer2": log_entry.layer2_result,
            "layer3": log_entry.layer3_result,
            "final_verdict": log_entry.final_verdict,
            "risk_flags": log_entry.risk_flags,
            "execution_time_ms": log_entry.execution_time_ms,
        }
        self._records.append(record)

        # 追加写入 JSONL
        with open(self.log_path, "a", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
            f.write("\n")

        return log_entry.trace_id

    def get_recent(self, n: int = 10) -> List[Dict]:
        """获取最近 N 条记录"""
        return self._records[-n:]

    def filter(self, verdict: str = None, agent: str = None,
               risk_level: str = None, hours: int = None) -> List[Dict]:
        """按条件筛选"""
        results = self._records
        if verdict:
            results = [r for r in results if verdict in r.get("final_verdict", "")]
        if agent:
            results = [r for r in results if r.get("agent_name") == agent]
        if risk_level:
            results = [r for r in results if any(
                layer and layer.get("risk", "") == risk_level
                for layer in [r.get("layer1"), r.get("layer2"), r.get("layer3")]
            )]
        if hours:
            cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
            results = [r for r in results if r.get("timestamp", "") > cutoff]
        return results

    def analyze_frequent_issues(self, limit: int = 10) -> Dict:
        """分析高频问题（JD 职责 3: 统计并分析高频问题输出）"""
        block_reasons = Counter()
        agent_stats = defaultdict(lambda: {"total": 0, "blocked": 0})

        for r in self._records:
            agent = r.get("agent_name", "unknown")
            agent_stats[agent]["total"] += 1
            if "blocked" in r.get("final_verdict", ""):
                agent_stats[agent]["blocked"] += 1
                for flag in r.get("risk_flags", []):
                    block_reasons[flag] += 1

        return {
            "total_records": len(self._records),
            "blocked": sum(1 for r in self._records if "blocked" in r.get("final_verdict", "")),
            "passed": sum(1 for r in self._records if r.get("final_verdict") == "passed"),
            "top_block_reasons": block_reasons.most_common(limit),
            "agent_stats": dict(agent_stats),
        }

    def replay_trace(self, trace_id: str) -> Optional[Dict]:
        """回放指定决策轨迹"""
        for r in self._records:
            if r.get("trace_id") == trace_id:
                return {
                    "trace": r,
                    "timeline": self._build_timeline(r)
                }
        return None

    def _build_timeline(self, record: Dict) -> List[str]:
        """构建决策时间线"""
        timeline = [f"[{record['timestamp']}] Input: {record['input_preview'][:100]}"]
        for layer_name, layer_key in [("L1", "layer1"), ("L2", "layer2"), ("L3", "layer3")]:
            layer = record.get(layer_key)
            if layer:
                status = "PASS" if layer.get("passed") else "BLOCK"
                risk = layer.get("risk", "?")
                timeline.append(f"  [{layer_name}] {status} (risk={risk}) — {layer.get('summary', '')}")
        timeline.append(f"  VERDICT: {record['final_verdict']}")
        return timeline
