from typing import Optional

from pydantic import BaseModel

class User(BaseModel):
    name: str
    surname: str
    password: str
    email: str
    is_enabled: str
    otp: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    token_otp: Optional[str] = None

class OtpRequest(BaseModel):
    username: str
    password: str


class RegisterUser(BaseModel):
    name: str
    surname: str
    email: str
    password: str
    password_confirmation: str

