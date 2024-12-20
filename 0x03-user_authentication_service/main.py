#!/usr/bin/env python3
"""Testing module for user authentication and session management."""

import requests


def register_user(email: str, password: str) -> None:
    """Register a new user.

    Args:
        email (str): The user's email address.
        password (str): The user's password.

    Asserts:
        The response status code is 200.
        The response JSON matches the expected output.
    """
    r = requests.post('http://127.0.0.1:5000/users', data={
        'email': email,
        'password': password
    })
    assert r.status_code == 200
    assert r.json() == {'email': email, 'message': "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Attempt to log in with an incorrect password.

    Args:
        email (str): The user's email address.
        password (str): An incorrect password.

    Asserts:
        The response status code is 401.
    """
    r = requests.post('http://127.0.0.1:5000/sessions', data={
        'email': email,
        'password': password
    })
    assert r.status_code == 401


def log_in(email: str, password: str) -> str:
    """Log in with correct credentials.

    Args:
        email (str): The user's email address.
        password (str): The user's password.

    Returns:
        str: The session ID from the response cookies.

    Asserts:
        The response status code is 200.
        The response JSON matches the expected output.
    """
    r = requests.post('http://127.0.0.1:5000/sessions', data={
        'email': email,
        'password': password
    })
    assert r.status_code == 200
    assert r.json() == {'email': email, 'message': "logged in"}
    # Parse the response cookie to return the session_id for other methods
    return r.cookies.get('session_id')


def profile_unlogged() -> None:
    """Attempt to access the profile page without being logged in.

    Asserts:
        The response status code is 403.
    """
    r = requests.get('http://127.0.0.1:5000/profile')
    assert r.status_code == 403


def profile_logged(session_id: str) -> None:
    """Access the profile page while logged in.

    Args:
        session_id (str): The session ID of the logged-in user.

    Asserts:
        The response status code is 200.
        The response JSON matches the expected output.
    """
    r = requests.get('http://127.0.0.1:5000/profile', cookies={
        'session_id': session_id
    })
    assert r.status_code == 200
    assert r.json() == {'email': "guillaume@holberton.io"}


def log_out(session_id: str) -> None:
    """Log out the user by deleting their session.

    Args:
        session_id (str): The session ID of the logged-in user.

    Asserts:
        A 302 redirect occurred in the response history.
    """
    r = requests.delete('http://127.0.0.1:5000/sessions', cookies={
        'session_id': session_id
    })
    # Check that a 302 redirect occurred during the response history
    for past_r in r.history:
        assert past_r.status_code == 302


def reset_password_token(email: str) -> str:
    """Request a password reset token.

    Args:
        email (str): The user's email address.

    Returns:
        str: The reset token from the response JSON.

    Asserts:
        The response status code is 200.
    """
    r = requests.post('http://127.0.0.1:5000/reset_password', data={
        'email': email,
    })
    assert r.status_code == 200
    # Return the reset_token for other methods
    return r.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update the user's password using a reset token.

    Args:
        email (str): The user's email address.
        reset_token (str): The reset token obtained earlier.
        new_password (str): The new password to set.

    Asserts:
        The response status code is 200.
        The response JSON matches the expected output.
    """
    r = requests.put('http://127.0.0.1:5000/reset_password', data={
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password
    })
    assert r.status_code == 200
    assert r.json() == {'email': email, 'message': "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
