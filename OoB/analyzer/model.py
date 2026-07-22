from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


#Possible actions (Never Honeypot)

Action = Literal["block", "reset"]
Verdict = Literal["Malicious", "Benign"]


@dataclass(frozen = True)
class Event:
    #Normalized Zeek log line

    path: str # "conn", "ssl", "dns", "http", "notice"
    data: dict[str, Any]

    @property
    def src_ip(self)-> str | None:
        return self.data.get("id.orig_h")

    @property
    def dts_ip(self)-> str | None:
        return self.data.get("id.resp_h")

    @property
    def dest_port(self) -> int | None:
        return self.data.get("id.reso_p")

    @property
    def uid (self) -> str | None: #uid = unique identifier (used to 
        return self.data.get("uid")

    @property
    def ts(self) -> str | None: #ts = timestamp
        # ISO8601 due to the config in mvp.zeek
        return self.data.get("ts")


@dataclass (frozen = True)
class Finding:

    #The result of a single detector on a single event
    # A finding is not a verdict. It's an observation with a score. the scoring system decides if they cross the threshold

    detector: str #what exactly made the discovery (example: sni_blocklist, ja3_blocklist)
    score:float #Contribution: 0.0 - 1.0
    reason: str # human_readable_reasoning
    src_ip: str
    mitre_tactic: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerdictReport:
    verdict: Verdict
    source_ip: str
    timestamp: str
    action_taken: Action
    human_readable_reasoning: str
    confidence_score: float | None = None
    mitre_tactic_identified: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "action_taken": self.action_taken,
            "human_readable_reasoning": self.human_readable_reasoning,
            "confidence_score": self.confidence_score,
            "mitre_tactic_identified": self.mitre_tactic_identified,
        }


def utc_now_iso() -> str:
    """UTC Timestamp in the same format as Zeek logs (ISO8601)."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )