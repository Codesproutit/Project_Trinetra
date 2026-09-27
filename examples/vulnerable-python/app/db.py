"""Deliberately vulnerable sample — SQL injection. DO NOT ship."""


def get_user(cursor, user_id):
    # Vulnerable: user input interpolated straight into SQL (CWE-89).
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
