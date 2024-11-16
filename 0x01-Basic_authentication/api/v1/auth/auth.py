#!/usr/bin/env python3
""" Module of Auth
"""
from typing import List, TypeVar
from flask import request
import re


class Auth():
    """Manage API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Public method require auth
        """
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        for element in excluded_paths:
            if "*" in element:
                return not(path.startswith(element.replace("*", "")))
        return not(path in excluded_paths or f'{path}/' in excluded_paths)

    def authorization_header(self, request=None) -> str:
        """public method
        """
        if request:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user method"""
        return None
