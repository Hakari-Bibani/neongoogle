# main.py
import streamlit as st
import requests
import logging
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from db_handler import run_command, run_query

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google OAuth secrets
GOOGLE_CLIENT_ID = st.secrets.google.client_id
GOOGLE_CLIENT_SECRET = st.secrets.google.client_secret
REDIRECT_URI = st.secrets.google.redirect_uri

def google_signin():
    """
    Minimal Google Sign-In using OAuth.
    """
    st.title("Sign In with Google")
    
    # If user is already logged in, skip sign-in
    if st.session_state.get("user", {}).get("email"):
        st.success(f"Signed in as {st.session_state['user']['email']}")
        return

    # Get query parameters using the new st.query_params
    query_params = st.query_params  # Updated from st.experimental_get_query_params()
    if "code" in query_params:
        _handle_oauth_callback(query_params["code"][0])
        return

    st.subheader("Click to Sign in with Google")
    auth_url = _generate_auth_url()
    st.write(f"[**Continue to Google**]({auth_url})")

def _generate_auth_url() -> str:
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    scope = "openid%20email%20profile"
    return (
        f"{base_url}"
        f"?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={scope}"
        f"&access_type=offline"
        f"&prompt=select_account"
    )

def _handle_oauth_callback(auth_code: str):
    if not auth_code:
        st.error("Missing authorization code.")
        return
    tokens = _exchange_code_for_tokens(auth_code)
    if not tokens or "id_token" not in tokens:
        st.error("Authentication failed.")
        return

    id_info = _validate_google_token(tokens["id_token"])
    if not id_info:
        return

    email = id_info["email"]
    name = id_info.get("name", email.split("@")[0])
    
    # Upsert user into the database (if needed)
    user_id = _get_or_create_user(name, email)
    
    # Save user info in session state
    st.session_state["user"] = {"id": user_id, "name": name, "email": email}
    
    # Clear query params using the new st.set_query_params
    st.set_query_params()  # Updated from st.experimental_set_query_params()
    st.success(f"Logged in as {name} ({email})")

def _exchange_code_for_tokens(auth_code: str) -> dict:
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
    except Exception as e:
        logger.error(f"Token exchange error: {str(e)}")
        st.error("Failed to exchange code for tokens.")
    return {}

def _validate_google_token(token: str) -> dict:
    try:
        id_info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )
        if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer.")
        if id_info["aud"] != GOOGLE_CLIENT_ID:
            raise ValueError("Mismatched client ID.")
        return id_info
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        st.error("Invalid ID token or mismatched credentials.")
    return None

def _get_or_create_user(username: str, email: str) -> int:
    """
    Check if user exists; if not, create a new user row.
    """
    query = "SELECT user_id FROM users WHERE email = %s"
    result = run_query(query, (email,))
    if result:
        return result[0][0]
    
    # Create new user. Occupation and country will be added later.
    insert_query = "INSERT INTO users (username, email) VALUES (%s, %s) RETURNING user_id"
    run_command(insert_query, (username, email))
    result = run_query(query, (email,))
    return result[0][0] if result else None

def main_page():
    """
    Displays the main page after authentication.
    """
    st.header("Here is the future so it is simple")
    st.write("Welcome to our app!")
    
    # Form to add occupation and country
    with st.form("user_details_form"):
        occupation = st.text_input("Occupation")
        country = st.text_input("Country")
        submitted = st.form_submit_button("Update Profile")
        if submitted:
            user = st.session_state.get("user")
            if user:
                update_query = """
                    UPDATE users
                    SET occupation = %s, country = %s
                    WHERE user_id = %s
                """
                run_command(update_query, (occupation, country, user["id"]))
                st.success("Profile updated!")
            else:
                st.error("User not found. Please sign in.")

def main():
    # Display Google sign-in if user not logged in
    if "user" not in st.session_state:
        google_signin()
    else:
        main_page()

if __name__ == "__main__":
    main()
