#!/usr/bin/env python3
"""
This module is used to encrypt the password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash the password
    Using: bcrypt package to perform the hashing
    """
    return bcrypt.hashpw(password.encode(),
                         bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if the password is valid
    Using: bcrypt package to perform the hashing
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
