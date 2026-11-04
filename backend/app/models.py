from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, Text, Float, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(150))
    role: Mapped[str] = mapped_column(String(30), default="reviewer")

class Employee(Base):
    __tablename__ = "employees"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    name: Mapped[str] = mapped_column(String(150))
    email: Mapped[str] = mapped_column(String(180), unique=True)
    department: Mapped[str] = mapped_column(String(80))
    job_title: Mapped[str] = mapped_column(String(100))
    manager_username: Mapped[str] = mapped_column(String(100), default="reviewer")
    status: Mapped[str] = mapped_column(String(30), default="active")
    accounts: Mapped[list["Account"]] = relationship(back_populates="employee")

class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (UniqueConstraint("platform", "username", name="uq_platform_username"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id"), nullable=True)
    platform: Mapped[str] = mapped_column(String(60), index=True)
    username: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(30), default="active")
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_source: Mapped[str | None] = mapped_column(String(80), nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    employee: Mapped[Employee | None] = relationship(back_populates="accounts")
    entitlements: Mapped[list["Entitlement"]] = relationship(back_populates="account")

class Entitlement(Base):
    __tablename__ = "entitlements"
    __table_args__ = (UniqueConstraint("account_id", "resource", "permission", name="uq_entitlement"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    resource: Mapped[str] = mapped_column(String(180))
    permission: Mapped[str] = mapped_column(String(60))
    sensitivity: Mapped[str] = mapped_column(String(30), default="medium")
    source: Mapped[str] = mapped_column(String(80), default="csv")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    evidence_source: Mapped[str | None] = mapped_column(String(80), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    account: Mapped[Account] = relationship(back_populates="entitlements")

class Activity(Base):
    __tablename__ = "activities"
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    resource: Mapped[str] = mapped_column(String(180))
    event_type: Mapped[str] = mapped_column(String(60))
    occurred_at: Mapped[datetime] = mapped_column(DateTime)
    source: Mapped[str] = mapped_column(String(80))

class Review(Base):
    __tablename__ = "reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    entitlement_id: Mapped[int] = mapped_column(ForeignKey("entitlements.id"))
    assigned_to: Mapped[str] = mapped_column(String(100), default="reviewer")
    state: Mapped[str] = mapped_column(String(30), default="pending")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    remediation_state: Mapped[str] = mapped_column(String(30), default="not_requested")
    remediation_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    entitlement: Mapped[Entitlement] = relationship()

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(80))
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
