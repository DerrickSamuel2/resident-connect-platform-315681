from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class TokenPair(BaseModel):
    access_token: str = Field(..., description="JWT access token (short-lived).")
    refresh_token: str = Field(..., description="JWT refresh token (long-lived).")
    token_type: str = Field("bearer", description="Token type; always 'bearer'.")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email (unique, case-insensitive).")
    password: str = Field(..., min_length=8, description="User password (min 8 chars).")
    role: str = Field(
        "resident",
        description="Initial role. Only 'resident' is allowed for self-registration.",
    )


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email.")
    password: str = Field(..., description="User password.")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token previously issued.")


class UserMe(BaseModel):
    id: UUID = Field(..., description="User UUID.")
    email: EmailStr = Field(..., description="Email address.")
    role: str = Field(..., description="User role: resident|admin.")
    is_active: bool = Field(..., description="Whether the account is active.")
    is_email_verified: bool = Field(..., description="Whether email is verified.")
    created_at: datetime = Field(..., description="Creation timestamp.")


class ProfilePrivacy(BaseModel):
    is_directory_visible: bool = Field(
        True, description="Whether profile appears in the directory."
    )
    show_email: bool = Field(
        False, description="Whether email is visible to other residents."
    )
    show_phone: bool = Field(
        False, description="Whether phone is visible to other residents."
    )
    show_unit: bool = Field(
        False, description="Whether unit/building are visible to other residents."
    )


class ProfileBase(BaseModel):
    first_name: Optional[str] = Field(None, description="Resident first name.")
    last_name: Optional[str] = Field(None, description="Resident last name.")
    phone: Optional[str] = Field(None, description="Phone number (optional).")
    bio: Optional[str] = Field(None, description="Short bio (optional).")
    building_id: Optional[UUID] = Field(None, description="Associated building UUID.")
    unit_id: Optional[UUID] = Field(None, description="Associated unit UUID.")
    privacy: ProfilePrivacy = Field(
        default_factory=ProfilePrivacy, description="Privacy controls."
    )
    consent_directory: bool = Field(
        True, description="Consent to be included in directory."
    )
    consent_messaging: bool = Field(
        True, description="Consent to receive/send messages."
    )
    consent_marketing: bool = Field(False, description="Consent to marketing emails.")


class ProfileUpdateRequest(ProfileBase):
    pass


class ProfileResponse(BaseModel):
    user_id: UUID = Field(..., description="User UUID owning the profile.")
    email: Optional[EmailStr] = Field(
        None, description="Email if allowed by privacy rules."
    )
    first_name: Optional[str] = Field(None, description="First name.")
    last_name: Optional[str] = Field(None, description="Last name.")
    phone: Optional[str] = Field(None, description="Phone if allowed by privacy rules.")
    bio: Optional[str] = Field(None, description="Bio.")
    building_id: Optional[UUID] = Field(None, description="Building UUID if allowed.")
    unit_id: Optional[UUID] = Field(None, description="Unit UUID if allowed.")
    is_directory_visible: bool = Field(..., description="Directory visibility flag.")
    show_email: bool = Field(..., description="Privacy flag for email.")
    show_phone: bool = Field(..., description="Privacy flag for phone.")
    show_unit: bool = Field(..., description="Privacy flag for unit/building.")
    consent_directory: bool = Field(..., description="Directory consent.")
    consent_messaging: bool = Field(..., description="Messaging consent.")
    consent_marketing: bool = Field(..., description="Marketing consent.")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp.")


class DirectorySearchResponse(BaseModel):
    results: List[ProfileResponse] = Field(..., description="Search results (redacted).")


class AnnouncementCreateRequest(BaseModel):
    title: str = Field(..., description="Announcement title.")
    body: str = Field(..., description="Announcement body content.")
    building_id: Optional[UUID] = Field(
        None, description="Restrict announcement to building (optional)."
    )
    is_pinned: bool = Field(False, description="Whether announcement is pinned.")


class AnnouncementResponse(BaseModel):
    id: UUID = Field(..., description="Announcement UUID.")
    title: str = Field(..., description="Title.")
    body: str = Field(..., description="Body.")
    author_id: Optional[UUID] = Field(None, description="Author user UUID.")
    building_id: Optional[UUID] = Field(None, description="Building UUID (optional).")
    is_pinned: bool = Field(..., description="Pinned flag.")
    published_at: datetime = Field(..., description="Publish timestamp.")


class EventCreateRequest(BaseModel):
    title: str = Field(..., description="Event title.")
    description: Optional[str] = Field(None, description="Event description.")
    building_id: Optional[UUID] = Field(None, description="Building UUID (optional).")
    starts_at: datetime = Field(..., description="Start datetime (ISO8601).")
    ends_at: Optional[datetime] = Field(None, description="End datetime (optional).")
    location: Optional[str] = Field(None, description="Location (optional).")


class EventResponse(BaseModel):
    id: UUID = Field(..., description="Event UUID.")
    title: str = Field(..., description="Title.")
    description: Optional[str] = Field(None, description="Description.")
    building_id: Optional[UUID] = Field(None, description="Building UUID (optional).")
    starts_at: datetime = Field(..., description="Start datetime.")
    ends_at: Optional[datetime] = Field(None, description="End datetime.")
    location: Optional[str] = Field(None, description="Location.")
    created_by: Optional[UUID] = Field(None, description="Creator user UUID.")


class AuditLogResponse(BaseModel):
    id: UUID = Field(..., description="Audit log UUID.")
    actor_user_id: Optional[UUID] = Field(None, description="Actor user UUID.")
    action: str = Field(..., description="Action name.")
    entity_type: Optional[str] = Field(None, description="Entity type.")
    entity_id: Optional[UUID] = Field(None, description="Entity UUID.")
    ip_address: Optional[str] = Field(None, description="IP address (best-effort).")
    user_agent: Optional[str] = Field(None, description="User agent (best-effort).")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata JSON.")
    created_at: datetime = Field(..., description="Timestamp.")


class GDPRRequestCreate(BaseModel):
    request_type: str = Field(..., description="Request type: export|delete.")


class GDPRRequestResponse(BaseModel):
    id: UUID = Field(..., description="GDPR request UUID.")
    user_id: UUID = Field(..., description="User UUID.")
    request_type: str = Field(..., description="Type: export|delete.")
    status: str = Field(..., description="Status.")
    requested_at: datetime = Field(..., description="Requested at.")
    completed_at: Optional[datetime] = Field(None, description="Completed at (if any).")
    export_data: Optional[Dict[str, Any]] = Field(
        None, description="Export payload when completed (if any)."
    )
