#!/usr/bin/env python3
"""
This module is used to encrypt the password
"""
import bcrypt


def hash_password(password: str) -> str:
    """
    Hash the password
    Using: bcrypt package to perform the hashing
    """
    return bcrypt.hashpw(password.encode('utf-8'),
                         bcrypt.gensalt()).decode('utf-8')
