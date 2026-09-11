from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    sender: str = Field(min_length=3, max_length=320)
    body: str = Field(min_length=1, max_length=200_000)
    header: str = Field(default="", max_length=200_000)

    @field_validator("sender")
    @classmethod
    def normalize_sender(cls, value: str) -> str:
        value = value.strip()
        if "\r" in value or "\n" in value:
            raise ValueError("sender must be a single line")
        return value


class FlaggedIssue(BaseModel):
    category: str
    severity: Literal["Critical", "Warning", "Informational"]
    description: str


class UncloakedUrl(BaseModel):
    original_url: str
    final_url: str
    is_suspicious: bool
    display_text: str | None = None


class AnalyzeResponse(BaseModel):
    overall_score: int = Field(ge=0, le=100)
    risk_level: Literal["Safe", "Moderate Risk", "Dangerous Phishing"]
    flagged_issues: list[FlaggedIssue]
    uncloaked_urls: list[UncloakedUrl]
    educational_advice: str
