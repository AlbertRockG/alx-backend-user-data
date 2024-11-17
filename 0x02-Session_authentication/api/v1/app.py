#!/usr/bin/env python3
"""
Route module for the API.

This module sets up the Flask application, configures CORS, handles authentication
based on the AUTH_TYPE environment variable, and defines error handlers and
request processing logic for the API.
"""

import os
from os import getenv
from flask import Flask, jsonify, abort, request
from flask_cors import CORS, cross_origin

from api.v1.views import app_views

# Initialize the Flask application
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True  # Enable pretty-printed JSON responses

# Register the blueprint containing the API views
app.register_blueprint(app_views)

# Configure Cross-Origin Resource Sharing (CORS) for the API
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize the authentication object based on the AUTH_TYPE environment variable
auth = None
AUTH_TYPE = getenv("AUTH_TYPE")

if AUTH_TYPE == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()
elif AUTH_TYPE == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif AUTH_TYPE == "session_auth":
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()
elif AUTH_TYPE == "session_exp_auth":
    from api.v1.auth.session_exp_auth import SessionExpAuth
    auth = SessionExpAuth()
elif AUTH_TYPE == "session_db_auth":
    from api.v1.auth.session_db_auth import SessionDBAuth
    auth = SessionDBAuth()


@app.errorhandler(401)
def unauthorized_error(error) -> tuple:
    """
    Handle Unauthorized (401) errors.

    Returns:
        A JSON response with an error message and a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden_error(error) -> tuple:
    """
    Handle Forbidden (403) errors.

    Returns:
        A JSON response with an error message and a 403 status code.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> tuple:
    """
    Handle Not Found (404) errors.

    Returns:
        A JSON response with an error message and a 404 status code.
    """
    return jsonify({"error": "Not found"}), 404


@app.before_request
def before_request() -> None:
    """
    Execute before each request to perform authentication and authorization.

    This function checks if the requested path requires authentication. If so, it verifies
    the presence of valid authentication credentials. If authentication fails, it aborts
    the request with the appropriate HTTP error code.

    Raises:
        401 Unauthorized: If authentication credentials are missing or invalid.
        403 Forbidden: If the authenticated user is not authorized to access the resource.
    """
    # If no authentication mechanism is set, proceed without authentication
    if auth is None:
        return

    # Define paths that are excluded from authentication
    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/'
    ]

    # Check if the current request path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Retrieve the authorization header or session cookie from the request
    if auth.authorization_header(request) is None and auth.session_cookie(request) is None:
        abort(401)  # Unauthorized if no valid credentials are provided

    # Retrieve the current user based on the authentication credentials
    current_user = auth.current_user(request)
    if current_user is None:
        abort(403)  # Forbidden if the user is not found or not authorized

    # Attach the current user to the request for use in view functions
    request.current_user = current_user


def main():
    """
    Entry point for running the Flask application.

    Retrieves the host and port from environment variables (defaulting to
    '0.0.0.0' and '5000' respectively) and starts the Flask development server.
    """
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
