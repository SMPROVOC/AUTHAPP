import os
from sqlalchemy import Column, Integer, String, and_, or_, not_
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv(override=True)
Base = declarative_base()

class User(Base):
    __tablename__ = os.getenv('USER_TABLE_NAME')
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    surname = Column(String(255))
    username = Column(String(255))
    email = Column(String(255))
    password = Column(String(255))
    is_enabled = Column(String(255))


class Settings(Base):
    __tablename__ = os.getenv('SETTINGS_TABLE_NAME')
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    value = Column(String(255))
    description = Column(String(255))


class Auth(Base):
    __tablename__ = os.getenv('AUTH_TABLE_NAME')
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255))
    otp = Column(String(2555))
    token = Column(String(255))
    created_at = Column(String(255))
    deleted_at = Column(String(255))
    state = Column(String(255))
