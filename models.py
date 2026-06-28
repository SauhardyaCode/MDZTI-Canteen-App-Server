from typing import List, Optional
from pydantic import BaseModel, Field

class SettingsItem(BaseModel):
    key: str
    value: str

class TraineeInfo(BaseModel):
    name: str
    designation: str
    course_start: str
    course_end: str
    meal_preference: str

class ScanItem(BaseModel):
    assignment_id: int
    date: str
    time: str
    meal_type: str

class SettingsPayload(BaseModel):
    settings: List[SettingsItem]

class GenerateTokensPayload(BaseModel):
    total_tokens: int

class AssignTokenPayload(BaseModel):
    token_number: int
    trainee: TraineeInfo

class VerifyScannedTokenPayload(BaseModel):
    token_id: str

class VerifyTypedTokenPayload(BaseModel):
    token_number: int

class SpecialConfigPayload(BaseModel):
    token_number_arr: List[int]
    date_interval_arr: List[str]
    breakfast_time_slot: Optional[str] = None
    lunch_time_slot: Optional[str] = None
    dinner_time_slot: Optional[str] = None
    is_suspended: Optional[bool] = None

class ChangeCourseIntervalPayload(BaseModel):
    token_number_arr: List[int]
    new_end_date: str

class UnassignTokenPayload(BaseModel):
    token_numbers: List[int]

class DestroyTokenPayload(BaseModel):
    token_number: int
    replaced_token_number: Optional[int] = None

class SyncNudgePayload(BaseModel):
    last_sync_str: str
    scans: Optional[List[ScanItem]] = None