import streamlit as st
import requests
import logging
import psycopg2
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import urllib.parse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google OAuth secrets from .streamlit/secrets.toml
GOOGLE_CLIENT_ID = st.secrets["google"]["client_id"]
GOOGLE_CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI = st.secrets["google"]["redirect_uri"]

# Neon database connection string from secrets
NEON_CONNECTION_STRING = st.secrets["neon"]["connection_string"]

# ----------------------- Database Functions -----------------------
def get_db_connection():
    """Establish a connection to the Neon PostgreSQL database."""
    try:
        conn = psycopg2.connect(NEON_CONNECTION_STRING)
        return conn
    except Exception as e:
        st.error("Database connection error.")
        logger.error(f"Database connection error: {e}")
        return None

def run_query(query, params=None):
    """Executes a SQL query and returns all rows."""
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            try:
                result = cur.fetchall()
            except psycopg2.ProgrammingError:
                # No results to fetch (e.g. for queries without a result set)
                result = []
            conn.commit()
            return result
    except Exception as e:
        logger.error(f"Database query error: {e}")
        st.error("Database query error.")
        return None
    finally:
        conn.close()

def run_command_returning(query, params=None):
    """Executes a SQL command and returns a single row (e.g., new ID)."""
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            try:
                returning_data = cur.fetchone()
            except psycopg2.ProgrammingError:
                returning_data = None
            conn.commit()
            return returning_data
    except Exception as e:
        logger.error(f"Database command error: {e}")
        st.error("Database command error.")
        return None
    finally:
        conn.close()

def create_users_table():
    """Creates the users table if it doesn't exist."""
    create_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        username TEXT NOT NULL
    );
    """
    run_query(create_table_query)

# ----------------------- Google OAuth Functions -----------------------
def google_signin():
    st.title("Sign In with Google")
    
    # Ensure the users table exists
    create_users_table()
    
    # Check if user is already logged in
    if st.session_state.get("user", {}).get("email"):
        st.success(f"You are already signed in as {st.session_state['user']['full_name']}")
        st.write("here is the future")
        return

    # Use the new API for query parameters
    query_params = st.query_params

    # Handle OAuth callback if a code is present
    if "code" in query_params:
        _handle_oauth_callback(query_params["code"][0])
        return

    st.subheader("Click to Sign in with Google")
    auth_url = _generate_auth_url()
    st.write(f"[**Continue to Google**]({auth_url})")

def _generate_auth_url() -> str:
    """Generates the Google OAuth URL for redirection."""
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    scope = "openid email profile"
    params = {
        "response_type": "code",
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "access_type": "offline",
        "prompt": "select_account"
    }
    return f"{base_url}?{urllib.parse.urlencode(params)}"

def _handle_oauth_callback(auth_code: str):
    """Handles the OAuth callback: exchanges the code for tokens and processes the user."""
    if not auth_code:
        st.error("Missing authorization code. Please try again.")
        return

    tokens = _exchange_code_for_tokens(auth_code)
    if not tokens or "id_token" not in tokens:
        st.error("No ID token in response. Sign-in failed.")
        return

    # Validate the Google ID token
    id_info = _validate_google_token(tokens["id_token"])
    if not id_info:
        return

    email = id_info.get("email")
    full_name = id_info.get("name", email.split("@")[0])
    username = email.split("@")[0]  # Derive a simple username from email

    # Save or retrieve the user in your Neon database
    user_id = _get_or_create_user(email, full_name, username)
    st.session_state["user"] = {
        "id": user_id,
        "email": email,
        "full_name": full_name,
        "username": username
    }

    # Clear query parameters to tidy up the URL using the new API
    st.set_query_params()

    st.success(f"Logged in as {full_name} ({email})")
    st.write("here is the future")

def _exchange_code_for_tokens(auth_code: str) -> dict:
    """Exchanges the authorization code for access and ID tokens."""
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": auth_code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    try:
        resp = requests.post(token_url, data=data, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"Token exchange HTTP error: {e.response.text}")
        st.error("Failed to exchange code for tokens.")
    except Exception as e:
        logger.error(f"Token exchange exception: {str(e)}")
        st.error("Failed to contact Google servers.")
    return {}

def _validate_google_token(token: str) -> dict:
    """Validates the Google ID token using google-auth."""
    try:
        id_info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )
        if id_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer.")
        if id_info.get("aud") != GOOGLE_CLIENT_ID:
            raise ValueError("Mismatched client ID.")
        return id_info
    except ValueError as e:
        logger.error(f"Token validation error: {str(e)}")
        st.error("Invalid ID token or mismatched credentials.")
    except Exception as e:
        logger.error(f"Token processing error: {str(e)}")
        st.error("Failed to process token.")
    return None

def _get_or_create_user(email: str, full_name: str, username: str) -> int:
    """
    Checks if the user exists in the database; if not, creates a new user record.
    Returns the user_id.
    """
    select_query = "SELECT user_id FROM users WHERE email = %s;"
    existing = run_query(select_query, (email,))
    if existing and len(existing) > 0:
        return existing[0][0]
    insert_query = "INSERT INTO users (email, full_name, username) VALUES (%s, %s, %s) RETURNING user_id;"
    new_user = run_command_returning(insert_query, (email, full_name, username))
    return new_user[0] if new_user else 0

# ----------------------- Main App -----------------------
def main():
    google_signin()

if __name__ == "__main__":
    main()
