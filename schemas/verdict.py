from pydantic import BaseModel, Field
from typing import Literal, Optional

class SemgrepFinding(BaseModel):
    finding_id: str
    file: str
    line: int
    rule_id: str
    cwe_tag: Optional[str]
    severity: str
    snippet: str

class AgentVerdict(BaseModel):
    finding_id: str
    verdict: Literal["TP", "FP", "UNCERTAIN"]
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: str
    cwe_mismatch: bool
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    reasoning: str
    iterations: int = Field(ge=1, le=3)
    agent_role: Literal["scanner", "analyzer", "reporter"]
    schema_valid: bool
    tool_call_evaded: bool  # Qwen-specific metric