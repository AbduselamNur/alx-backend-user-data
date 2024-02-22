#!/usr/bin/env python3
"""
Route module for the API
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic authentication"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns the Base64 part of the Authorization header
        """
        if authorization_header is None or \
           type(authorization_header) is not str or \
           not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]
