import os

from sqlalchemy import Column, Integer, String, ForeignKey, Identity
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
Base = declarative_base()

class Users(Base):
    __tablename__ = "users_table"
    ID = Column(Integer, Identity(start=1, cycle=True), primary_key=True, index=True, unique=True)
    UID = Column(String(255), unique=True, nullable=False)
    First_Name = Column(String(255), nullable=False)
    Last_Name = Column(String(255), nullable=False)
    Gender = Column(String(255), nullable=False)
    DOB = Column(String(255), nullable=False)
    Email = Column(String(255), nullable=False)
    Cell_Number = Column(String(255), nullable=False)
    Password = Column(String(255), nullable=False)
    Created_at = Column(String(255), nullable=False)
    Updated_at = Column(String(255), nullable=False)
    Deleted_at = Column(String(255), nullable=False)
    user_settings = relationship("Settings", back_populates="users")


class Settings(Base):
    __tablename__ = "settings_table"
    ID = Column(Integer, Identity(start=1, cycle=True), primary_key=True, index=True, unique=True)
    UID = Column(String(255), ForeignKey("users_table.UID"), unique=True, nullable=False)
    Is_enabled = Column(String(255), nullable=False)    # enabled/disabled
    Auth_type = Column(String(255), nullable=False)  # can be basic or multi factor
    Acc_verified = Column(String(255), nullable=False)  # can be verified/pending with verification link link
    Text_alerts = Column(String(255), nullable=False)   # enabled/disabled
    Whatsapp_alerts = Column(String(255), nullable=False)   # enabled/disabled
    Email_alerts = Column(String(255), nullable=False)  # enabled/disabled
    Device_name = Column(String(255), nullable=False)
    Device_id = Column(String(255), nullable=False)
    Created_at = Column(String(255), nullable=False)
    Updated_at = Column(String(255), nullable=False)
    Deleted_at = Column(String(255), nullable=False)
    users = relationship("Users", back_populates="user_settings")


class OTP(Base):
    __tablename__ = "otp_table"
    ID = Column(Integer, Identity(start=1, cycle=True), primary_key=True, index=True)
    User_id = Column(String(255))
    OTP = Column(String(2000))
    Token = Column(String(2500))
    State = Column(String(255))
    Created_at = Column(String(255))
    Deleted_at = Column(String(255))
