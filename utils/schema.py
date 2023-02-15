from pydantic import BaseModel
from typing import Optional

class ShowGreeting(BaseModel):
    greeting: str

    class Config():
        orm_mode = True


class User(BaseModel):
    name: str
    surname: str
    password: str
    email: str
    is_enabled: str
    otp: str


class UserRegistration(BaseModel):
    First_Name: str
    Last_Name: str
    Gender: str
    DOB: str
    Email: str
    Cell_Number: str
    Password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    token_info: Optional[str] = None