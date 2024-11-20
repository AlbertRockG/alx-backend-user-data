#!/usr/bin/env python3
"""Module for User ORM model using SQLAlchemy."""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    Represents a user in the database.

    Attributes:
        __tablename__ (str): Name of the table in the database.
        id (Column): Primary key column.
        email (Column): User's email address.
        hashed_password (Column): User's hashed password.
        session_id (Column): Session identifier.
        reset_token (Column): Password reset token.
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250))
    reset_token = Column(String(250))
