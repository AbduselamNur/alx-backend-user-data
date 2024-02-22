#!/usr/bin/env python3
""" Module of Auth views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request


class Auth:
    """ Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth
        """
        return False
    
    def authorization_header(self, request=None) -> str:
        """ authorization_header
        """
        return None
    
    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        return None
