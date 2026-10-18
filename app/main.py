"""
Adverse Event (AE) Intake API — Pharmacovigilance demo service.

Receives individual case safety report (ICSR) intake data, validates the
four ICH E2D minimum criteria for a valid case (identifiable patient,
identifiable reporter, suspect product, adverse event), flags serious
cases for 15-day expedited reporting, and writes a tamper-evident audit
trail (hash-chained), in the spirit of 21 CFR Part 11.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ae-intake")

APP_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Security: API key comes from the environment / a K8s Secret, never the code.
# --------------------------------------------------------------------------- #
def _expected_api_key() -> str:
    # Preferred: key mounted as a file from a K8s Secret / vault. Fallback: env var.
    key_file = os.environ.get("AE_API_KEY_FILE")
    if key_file and os.path.isfile(key_file):
        with open(key_file, encoding="utf-8") as fh:
            key = fh.read().strip()
    else:
        key = os.environ.get("AE_API_KEY", "")
    if not key:
        # Fail closed: no key configured means nobody gets in.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Service not configured")
    return key


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> str:
    expected = _expected_api_key()
    # Constant-time comparison to avoid timing attacks.
    if not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")
    return "api-client"


# --------------------------------------------------------------------------- #
# Domain model
# --------------------------------------------------------------------------- #
class Sex(str, Enum):
    male = "M"
    female = "F"
    unknown = "U"


class ReporterType(str, Enum):
    physician = "physician"
    pharmacist = "pharmacist"
    other_hcp = "other_hcp"
    consumer = "consumer"
    lawyer = "lawyer"


class Seriousness(str, Enum):
    death = "death"
    life_threatening = "life_threatening"
    hospitalisation = "hospitalisation"
    disability = "disability"
    congenital_anomaly = "congenital_anomaly"
    other_medically_important = "other_medically_important"


class Patient(BaseModel):
    model_config = ConfigDict(extra="forbid")
    initials: Optional[str] = Field(default=None, max_length=5, pattern=r"^[A-Za-z]{1,5}$")
    age_years: Optional[int] = Field(default=None, ge=0, le=120)
    sex: Sex = Sex.unknown

    def is_identifiable(self) -> bool:
        return bool(self.initials) or self.age_years is not None or self.sex != Sex.unknown


class Reporter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: ReporterType
    country: str = Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")


class AdverseEventReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    patient: Patient
    reporter: Reporter
    suspect_product: str = Field(min_length=2, max_length=200)
    reaction: str = Field(min_length=2, max_length=500, description="Verbatim reaction term")
    onset_date: Optional[date] = None
    seriousness: list[Seriousness] = Field(default_factory=list)
    narrative: Optional[str] = Field(default=None, max_length=5000)

    @field_validator("onset_date")
    @classmethod
    def onset_not_in_future(cls, v: Optional[date]) -> Optional[date]:
        if v and v > date.today():
            raise ValueError("onset_date cannot be in the future")
        return v


class CaseResponse(BaseModel):
    case_id: str
    received_at: datetime
    is_serious: bool
    expedited: bool
    regulatory_due_date: date
    status: str


# --------------------------------------------------------------------------- #
# Storage + tamper-evident audit trail (in-memory for the demo)
# --------------------------------------------------------------------------- #
class AuditTrail:
    """Append-only, hash-chained log. Altering any entry breaks the chain."""

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, actor: str, action: str, case_id: str) -> dict:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else "0" * 64
            entry = {
                "seq": len(self._entries) + 1,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "action": action,
                "case_id": case_id,
                "prev_hash": prev,
            }
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            self._entries.append(entry)
            return entry

    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._entries)

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries():
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev_hash"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


CASES: dict[str, dict] = {}
AUDIT = AuditTrail()

app = FastAPI(
    title="PV Adverse Event Intake API",
    version=APP_VERSION,
    description="Pharmacovigilance ICSR intake service (DevSecOps demo).",
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": APP_VERSION}


@app.post(
    "/api/v1/adverse-events",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_adverse_event(report: AdverseEventReport, actor: str = Depends(require_api_key)) -> CaseResponse:
    # ICH E2D minimum criteria: patient, reporter, product, event.
    if not report.patient.is_identifiable():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Invalid case: patient must be identifiable (initials, age or sex)",
        )

    received = datetime.now(timezone.utc)
    is_serious = len(report.seriousness) > 0
    # Serious cases -> 15-calendar-day expedited report; otherwise periodic (90 days here).
    due = received.date() + timedelta(days=15 if is_serious else 90)
    case_id = f"AE-{received:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"

    CASES[case_id] = {
        "case_id": case_id,
        "received_at": received.isoformat(),
        "report": report.model_dump(mode="json"),
        "is_serious": is_serious,
        "regulatory_due_date": due.isoformat(),
    }
    AUDIT.record(actor, "CASE_CREATED", case_id)
    # Never log the narrative or patient details — only the case id.
    log.info("case created id=%s serious=%s", case_id, is_serious)

    return CaseResponse(
        case_id=case_id,
        received_at=received,
        is_serious=is_serious,
        expedited=is_serious,
        regulatory_due_date=due,
        status="received",
    )


@app.get("/api/v1/adverse-events/{case_id}")
def get_adverse_event(case_id: str, actor: str = Depends(require_api_key)) -> dict:
    case = CASES.get(case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    AUDIT.record(actor, "CASE_VIEWED", case_id)
    return case


@app.get("/api/v1/audit")
def get_audit_trail(actor: str = Depends(require_api_key)) -> dict:
    return {"chain_valid": AUDIT.verify(), "entries": AUDIT.entries()}
