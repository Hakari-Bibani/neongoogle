import streamlit as st
import requests
import logging
import psycopg2
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# --- Logging Config ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Google OAuth Credentials from secrets.toml ---
GOOGLE_CLIENT_ID = st.secrets["google"]["client_id"]
GOOGLE_CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI = st.secrets["google"]["redirect_uri"]

# --- Neon DB Connection String ---
DB_CONNECTION_STRING = st.secrets["neon"]["connection_string"]

# --- Google OAuth Functions ---
def google_signin():
    st.title("Sign In with Google")
    
    # If the user is already signed in, skip OAuth
    if st.session_state.get("user", {}).get("email"):
        st.success(f"Already signed in as {st.session_state['user']['email']}")
        return

    # Get query parameters (e.g., the auth code)
    query_params = st.experimental_get_query_params()
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
        st.error("Missing authorization code. Please try again.")
        return

    tokens = _exchange_code_for_tokens(auth_code)
    if not tokens or "id_token" not in tokens:
        st.error("Authentication failed. No ID token.")
        return

    # Validate Google ID token
    id_info = _validate_google_token(tokens["id_token"])
    if not id_info:
        return

    email = id_info["email"]
    st.session_state["user"] = {
        "google_id": id_info.get("sub"),
        "email": email,
        "name": id_info.get("name", email.split("@")[0])
    }

    # Clear query parameters to clean up the URL
    st.experimental_set_query_params()
    st.success(f"Logged in as {st.session_state['user']['name']}")

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
        logger.error(f"Token exchange error: {e}")
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
            st.error("Invalid token issuer.")
            return None
        return id_info
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        st.error("Token validation failed.")
        return None

# --- Database Function ---
def insert_user_info(fullname, occupation, country, user_email, google_id):
    try:
        conn = psycopg2.connect(DB_CONNECTION_STRING)
        cur = conn.cursor()
        # Insert or update record (using ON CONFLICT for unique google_id)
        query = """
        INSERT INTO users (google_id, email, fullname, occupation, country)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (google_id) DO UPDATE SET
            fullname = EXCLUDED.fullname,
            occupation = EXCLUDED.occupation,
            country = EXCLUDED.country;
        """
        cur.execute(query, (google_id, user_email, fullname, occupation, country))
        conn.commit()
        cur.close()
        conn.close()
        st.success("Your information has been recorded.")
    except Exception as e:
        logger.error(f"Database error: {e}")
        st.error("Failed to record your information.")

# --- Main App Page ---
def main_page():
    st.title("Welcome to the Future")
    st.write("Here is the future: add your details below.")

    # Check if the user is authenticated.
    if "user" not in st.session_state:
        st.info("Please sign in first.")
        google_signin()
    else:
        user = st.session_state["user"]
        st.write(f"Hello, {user['name']}!")

        with st.form("user_info_form"):
            fullname = st.text_input("Full Name")
            occupation = st.text_input("Occupation")
            country = st.text_input("Country")
            submitted = st.form_submit_button("Submit")
            if submitted:
                if fullname and occupation and country:
                    insert_user_info(fullname, occupation, country, user["email"], user["google_id"])
                else:
                    st.error("Please fill in all fields.")

if __name__ == '__main__':
    main_page()
