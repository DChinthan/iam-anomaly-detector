"""
Lightweight role-based access control for the Streamlit dashboard.

A tool that detects IAM privilege misuse should not itself be wide open —
this gives the dashboard its own least-privilege access model:

  admin   - full access: retrain/regenerate controls, GenAI alerts, raw tables
  analyst - GenAI alerts and flagged-user detail, no retrain controls
  viewer  - aggregate metrics and charts only, no user-identifying data

Credentials are defined via the DASHBOARD_USERS env var as
"user:password:role,user:password:role,...". This is a demo/dev-grade gate
(SHA-256 hashed, in-memory, no session persistence beyond the browser tab)
— for a real deployment, swap this for AWS Cognito (see infra/terraform/cognito.tf)
or an SSO provider in front of the app.
"""
import hashlib
import os
from typing import Optional

import streamlit as st

DEFAULT_USERS = "admin:admin123:admin,analyst:analyst123:analyst,viewer:viewer123:viewer"

ROLE_PERMISSIONS = {
    "admin": {"retrain", "view_genai", "view_user_ids", "view_raw_table"},
    "analyst": {"view_genai", "view_user_ids"},
    "viewer": set(),
}


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _parse_users() -> dict:
    raw = os.getenv("DASHBOARD_USERS", DEFAULT_USERS)
    users = {}
    for entry in raw.split(","):
        username, password, role = entry.split(":")
        users[username] = {"password_hash": _hash(password), "role": role}
    return users


def current_user() -> Optional[dict]:
    return st.session_state.get("auth_user")


def require_login() -> dict:
    """Renders a login form until authenticated, then returns {username, role}.
    Call st.stop() has already happened internally if unauthenticated."""
    user = current_user()
    if user:
        st.sidebar.success(f"Signed in as **{user['username']}** ({user['role']})")
        if st.sidebar.button("Sign out"):
            del st.session_state["auth_user"]
            st.rerun()
        return user

    st.sidebar.subheader("🔐 Sign in")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Sign in"):
        record = _parse_users().get(username)
        if record and record["password_hash"] == _hash(password):
            st.session_state["auth_user"] = {"username": username, "role": record["role"]}
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")

    st.sidebar.caption(
        "Demo accounts — admin/admin123, analyst/analyst123, viewer/viewer123"
    )
    st.title("AWS IAM Anomaly Detection Dashboard")
    st.info("Please sign in from the sidebar to view the dashboard.")
    st.stop()


def can(user: dict, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user["role"], set())
