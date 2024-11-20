#!/usr/bin/env python3
"""Flask app module for user authentication and session management."""

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def hello_world() -> str:
    """Return a welcome message."""
    msg = {"message": "Bienvenue"}
    return jsonify(msg)


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """Register a new user.

    Expects 'email' and 'password' in the form data.

    Returns:
        JSON response with user's email and a success message.
        If the email is already registered, returns a 400 status code.
    """
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    try:
        user = AUTH.register_user(email, password)
        msg = {"email": email, "message": "user created"}
        return jsonify(msg)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Log in a user and create a new session.

    Expects 'email' and 'password' in the form data.

    Returns:
        JSON response with user's email and a success message.
        Sets a cookie with the session ID.
        If login fails, returns a 401 status code.
    """
    form_data = request.form
    email = form_data.get("email")
    password = form_data.get("password")

    if not email or not password:
        return jsonify({"message": "email and password required"}), 400

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie('session_id', session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def log_out() -> None:
    """Log out a user by destroying their session.

    Requires a valid 'session_id' cookie.

    Returns:
        Redirects to the root URL.
        If the session is invalid, returns a 403 status code.
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Retrieve the profile of the logged-in user.

    Requires a valid 'session_id' cookie.

    Returns:
        JSON response with the user's email.
        If the session is invalid, returns a 403 status code.
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Generate a password reset token for a user.

    Expects 'email' in the form data.

    Returns:
        JSON response with the user's email and reset token.
        If the user does not exist, returns a 403 status code.
    """
    try:
        email = request.form['email']
    except KeyError:
        abort(400)

    try:
        reset_token = AUTH.get_reset_password_token(email)
        msg = {"email": email, "reset_token": reset_token}
        return jsonify(msg), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Update a user's password using a reset token.

    Expects 'email', 'reset_token', and 'new_password' in the form data.

    Returns:
        JSON response with the user's email and a success message.
        If the reset token is invalid, returns a 403 status code.
    """
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
        msg = {"email": email, "message": "Password updated"}
        return jsonify(msg), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
