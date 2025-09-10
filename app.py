import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, session, request, flash

from descope import DescopeClient
from descope.exceptions import AuthException
from descope.common import DeliveryMethod as Method # For Magic Link

import google.generativeai as genai
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import datetime
import json


# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Descope Configuration ---
descope_project_id = os.getenv("DESCOPE_PROJECT_ID")
descope_management_key = os.getenv("DESCOPE_MANAGEMENT_KEY")

if not descope_project_id or not descope_management_key:
    raise ValueError("DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY must be set in the .env file")

try:
    descope_client = DescopeClient(project_id=descope_project_id, management_key=descope_management_key)
except AuthException as e:
    print(f"Failed to initialize DescopeClient: {e}")
    exit(1)

# --- Google Gemini Configuration ---
google_api_key = os.getenv("GOOGLE_API_KEY")
if not google_api_key:
    raise ValueError("GOOGLE_API_KEY must be set in the .env file for Gemini access")
genai.configure(api_key=google_api_key)


# --- Google Calendar Direct OAuth Configuration ---
GOOGLE_CALENDAR_REDIRECT_URI = "http://127.0.0.1:5000/google-calendar/callback"

# Load Google Client ID and Secret directly from .env for the native Google OAuth flow
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in the .env file for Google Calendar API")


GOOGLE_OAUTH_SCOPES = [
    'https://www.googleapis.com/auth/calendar.events', # To create, modify, delete events
    'https://www.googleapis.com/auth/calendar.readonly', # To read calendar info
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',   # Explicitly request email scope this way
    'https://www.googleapis.com/auth/userinfo.profile'  # Explicitly request profile scope this way
]

# --- Descope Social Login IDPs (Verify these exact strings in your Descope Console under Social & Enterprise Logins) ---
GOOGLE_SOCIAL_IDP_ID = "google"
MICROSOFT_SOCIAL_IDP_ID = "microsoft"
GITHUB_SOCIAL_IDP_ID = "github"


# Helper function to set Descope session tokens
def set_descope_session(jwt_response):
    session_token_dict = jwt_response.get("sessionToken", {})
    session_token = session_token_dict.get("jwt")

    refresh_token_dict = jwt_response.get("refreshSessionToken", {})
    refresh_token = refresh_token_dict.get("jwt")
    
    user_id = jwt_response.get("user", {}).get("userId")
    user_email = jwt_response.get("user", {}).get("email")

    if not session_token or not refresh_token:
        return False, "Did not receive valid tokens after Descope verification."

    session['user_id'] = user_id
    session['user_email'] = user_email
    session['session_token'] = session_token
    session['refresh_token'] = refresh_token
    return True, "Successfully logged in!"


# Define the home page route
@app.route('/')
def home():
    """
    Renders the home page, showing login/signup form or user info if logged in.
    Flashes messages to the user.
    """
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    
    return render_template('index.html',
                           descope_project_id=descope_project_id,
                           user_id=user_id,
                           user_email=user_email)

# Route to send the magic link (for signup/login)
@app.route('/send-magic-link', methods=['POST'])
def send_magic_link():
    """
    Initiates the Magic Link authentication flow with Descope.
    """
    email = request.form.get('email')
    if not email:
        flash("Email is required to send a magic link.", 'error')
        return redirect(url_for('home'))

    try:
        callback_uri = url_for('auth_callback', _external=True)
        print(f"\n--- DEBUG: Flask generated Magic Link Callback URI: {callback_uri} ---\n")

        descope_client.magiclink.sign_in(
            method=Method.EMAIL,
            login_id=email,
            uri=callback_uri
        )
        flash(f"Magic link sent to {email}. Please check your inbox and click the link to log in.", 'info')
        return redirect(url_for('home'))

    except AuthException as e:
        flash(f"Failed to send magic link: {e.error_message}", 'error')
        print(f"Descope API error for magic link sending: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'error')
        print(f"Unexpected error when sending magic link: {e}")
        return redirect(url_for('home'))

# Route for Email + Password Sign Up
@app.route('/signup-password', methods=['POST'])
def signup_password():
    email = request.form.get('email')
    password = request.form.get('password')
    if not email or not password:
        flash("Email and password are required for sign up.", 'error')
        return redirect(url_for('home'))

    try:
        jwt_response = descope_client.password.sign_up(login_id=email, password=password)
        success, message = set_descope_session(jwt_response)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
        return redirect(url_for('home'))

    except AuthException as e:
        flash(f"Sign up failed: {e.error_message}", 'error')
        print(f"Descope API error for password sign up: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during sign up: {e}", 'error')
        print(f"Unexpected error during password sign up: {e}")
        return redirect(url_for('home'))

# Route for Email + Password Login
@app.route('/login-password', methods=['POST'])
def login_password():
    email = request.form.get('email')
    password = request.form.get('password')
    if not email or not password:
        flash("Email and password are required for login.", 'error')
        return redirect(url_for('home'))

    try:
        jwt_response = descope_client.password.sign_in(login_id=email, password=password)
        success, message = set_descope_session(jwt_response)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
        return redirect(url_for('home'))

    except AuthException as e:
        flash(f"Login failed: {e.error_message}", 'error')
        print(f"Descope API error for password login: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during login: {e}", 'error')
        print(f"Unexpected error during password login: {e}")
        return redirect(url_for('home'))


# Route for initiating Google Social Login
@app.route('/social-login/google')
def social_login_google():
    try:
        redirect_url = descope_client.oauth.start(
            provider=GOOGLE_SOCIAL_IDP_ID,
            redirect_uri=url_for('auth_callback', _external=True)
        )
        flash("Redirecting to Google for social login...", 'info')
        return redirect(redirect_url)
    except AuthException as e:
        flash(f"Google social login failed to initiate: {e.error_message}", 'error')
        print(f"Descope API error for Google social login: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during Google social login initiation: {e}", 'error')
        print(f"Unexpected error for Google social login: {e}")
        return redirect(url_for('home'))

# Route for initiating Microsoft (Outlook) Social Login
@app.route('/social-login/microsoft')
def social_login_microsoft():
    try:
        redirect_url = descope_client.oauth.start(
            provider=MICROSOFT_SOCIAL_IDP_ID,
            redirect_uri=url_for('auth_callback', _external=True)
        )
        flash("Redirecting to Microsoft for social login...", 'info')
        return redirect(redirect_url)
    except AuthException as e:
        flash(f"Microsoft social login failed to initiate: {e.error_message}", 'error')
        print(f"Descope API error for Microsoft social login: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during Microsoft social login initiation: {e}", 'error')
        print(f"Unexpected error for Microsoft social login: {e}")
        return redirect(url_for('home'))

# NEW: Route for initiating GitHub Social Login
@app.route('/social-login/github')
def social_login_github():
    try:
        redirect_url = descope_client.oauth.start(
            provider=GITHUB_SOCIAL_IDP_ID,
            redirect_uri=url_for('auth_callback', _external=True)
        )
        flash("Redirecting to GitHub for social login...", 'info')
        return redirect(redirect_url)
    except AuthException as e:
        flash(f"GitHub social login failed to initiate: {e.error_message}", 'error')
        print(f"Descope API error for GitHub social login: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during GitHub social login initiation: {e}", 'error')
        print(f"Unexpected error for GitHub social login: {e}")
        return redirect(url_for('home'))

# NEW: Placeholder route for Passkey registration/login initiation
@app.route('/passkey-action', methods=['GET', 'POST'])
def passkey_action():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first before attempting Passkey management.", 'info')
        return redirect(url_for('home'))
    
    flash("Passkey functionality requires Descope's client-side SDK for WebAuthn challenges. This button is a placeholder.", 'info')
    return redirect(url_for('home'))


# Route to handle the redirect from Descope after any authentication flow
@app.route('/auth/callback')
def auth_callback():
    """
    Handles the redirect from Descope after successful authentication.
    It can be a Magic Link (uses 't' parameter) or OAuth-based (uses 'code' parameter).
    """
    magic_link_token = request.args.get('t')
    oauth_code = request.args.get('code')
    
    jwt_response = None
    success = False
    message = "Authentication failed: An unknown error occurred."

    try:
        if magic_link_token:
            print(f"DEBUG: Verifying Magic Link token: {magic_link_token}")
            jwt_response = descope_client.magiclink.verify(token=magic_link_token)
            success, message = set_descope_session(jwt_response)
        elif oauth_code:
            print(f"DEBUG: Exchanging OAuth code: {oauth_code}")
            jwt_response = descope_client.oauth.exchange_token(code=oauth_code)
            success, message = set_descope_session(jwt_response)
        else:
            message = "Authentication failed: No authorization code or magic link token found in redirect."
            flash(message, 'error')
            print(f"DEBUG: {message}")
            return redirect(url_for('home'))

        flash(message, 'success' if success else 'error')
        return redirect(url_for('home'))

    except AuthException as e:
        flash(f"Authentication failed during callback verification: {e.error_message}", 'error')
        print(f"Descope callback verification failed: {e}")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"An unexpected error occurred during authentication callback: {e}", 'error')
        print(f"Unexpected error during Descope callback: {e}")
        return redirect(url_for('home'))


# Route to log out the user
@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the Flask session and invalidating the session with Descope.
    """
    refresh_token = session.get('refresh_token')

    if refresh_token:
        try:
            descope_client.logout(refresh_token=refresh_token)
            flash("Logged out successfully from Descope.", 'info')
        except AuthException as e:
            print(f"Descope logout failed: {e}")
            flash("Descope logout failed, but local session cleared.", 'error')
    
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('session_token', None)
    session.pop('refresh_token', None)
    # Clear Google Calendar tokens too
    if session.get('user_id'):
        session.pop(f'google_access_token_{session.get("user_id")}', None)
        session.pop(f'google_refresh_token_{session.get("user_id")}', None)

    flash("You have been logged out.", 'info')
    return redirect(url_for('home'))


# --- Google Calendar Integration (remains unchanged) ---

@app.route('/connect-google-calendar')
def connect_google_calendar():
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to connect your Google Calendar.", 'error')
        return redirect(url_for('home'))

    try:
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_CALENDAR_REDIRECT_URI]
                }
            },
            scopes=GOOGLE_OAUTH_SCOPES
        )
        flow.redirect_uri = GOOGLE_CALENDAR_REDIRECT_URI

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['google_oauth_state'] = state
        flash("Redirecting to Google for Calendar authorization...", 'info')
        return redirect(authorization_url)

    except Exception as e:
        flash(f"An unexpected error occurred while initiating Google Calendar connection: {e}", 'error')
        print(f"Error initiating Google OAuth flow: {e}")
        return redirect(url_for('home'))


@app.route('/google-calendar/callback')
def google_calendar_callback():
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to complete Google Calendar connection.", 'error')
        return redirect(url_for('home'))

    state = request.args.get('state')
    if state != session.get('google_oauth_state'):
        flash("Google Calendar connection failed: State mismatch.", 'error')
        print(f"State mismatch. Expected: {session.get('google_oauth_state')}, Received: {state}")
        return redirect(url_for('home'))
    session.pop('google_oauth_state', None)

    code = request.args.get('code')
    if not code:
        flash("Google Calendar connection failed: No authorization code found.", 'error')
        return redirect(url_for('home'))

    try:
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_CALENDAR_REDIRECT_URI]
                }
            },
            scopes=GOOGLE_OAUTH_SCOPES
        )
        flow.redirect_uri = GOOGLE_CALENDAR_REDIRECT_URI
        flow.fetch_token(code=code)

        creds = flow.credentials
        
        session[f'google_access_token_{user_id}'] = creds.token
        if creds.refresh_token:
            session[f'google_refresh_token_{user_id}'] = creds.refresh_token
        
        flash("Google Calendar connected successfully! You can now schedule actions.", 'success')
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"An unexpected error occurred during Google Calendar connection: {e}", 'error')
        print(f"Error during Google Calendar callback / token exchange: {e}")
        return redirect(url_for('home'))


# Route to extract action items using Gemini AI (remains unchanged)
@app.route('/extract-actions', methods=['POST'])
def extract_actions():
    """
    Receives meeting notes, sends them to Gemini for action item extraction,
    and returns the structured results. Requires user to be logged in.
    """
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to extract action items.", 'error')
        return redirect(url_for('home'))

    meeting_notes = request.form.get('meeting_notes')
    if not meeting_notes:
        flash("Please provide meeting notes to extract action items.", 'error')
        return redirect(url_for('home'))

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')

        prompt = f"""
        You are an expert meeting assistant. Your task is to extract clear, concise action items from the provided meeting notes.
        For each action item, identify:
        1. The task itself (what needs to be done).
        2. The assignee (who is responsible, if mentioned, otherwise "Unassigned").
        3. A suggested deadline (if mentioned, otherwise "End of next week").

        Format the output as a JSON array of objects. Example:
        [
            {{"task": "Review Q3 financial report", "assignee": "Sarah", "deadline": "Friday EOD"}},
            {{"task": "Schedule team sync", "assignee": "Unassigned", "deadline": "End of next week"}}
        ]

        Meeting Notes:
        {meeting_notes}
        """

        response = model.generate_content(prompt)
        
        response_text = response.text.strip()
        print(f"DEBUG: Raw Gemini response text: {response_text}")

        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        extracted_actions = json.loads(response_text)
        
        session['extracted_actions'] = extracted_actions
        flash("Action items extracted successfully! Now schedule them.", 'success')
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"Error processing notes with AI: {e}", 'error')
        print(f"Gemini AI error: {e}")
        return redirect(url_for('home'))


# Route to schedule a single action item in Google Calendar (remains unchanged)
@app.route('/schedule-action')
def schedule_action():
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to schedule actions.", 'error')
        return redirect(url_for('home'))

    google_access_token = session.get(f'google_access_token_{user_id}')
    google_refresh_token = session.get(f'google_refresh_token_{user_id}')

    if not google_access_token:
        flash("Google Calendar is not connected. Please connect it first.", 'error')
        return redirect(url_for('home'))

    creds = Credentials(google_access_token, refresh_token=google_refresh_token,
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=GOOGLE_CLIENT_ID,
                    client_secret=GOOGLE_CLIENT_SECRET)
    
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            session[f'google_access_token_{user_id}'] = creds.token
            flash("Google Calendar access token refreshed.", 'info')
        except Exception as e:
            flash(f"Failed to refresh Google Calendar token: {e}. Please reconnect.", 'error')
            return redirect(url_for('home'))
    elif creds.expired and not creds.refresh_token:
        flash("Google Calendar token expired and no refresh token available. Please reconnect.", 'error')
        return redirect(url_for('home'))


    task = request.args.get('task')
    assignee = request.args.get('assignee', 'Unassigned')
    deadline_str = request.args.get('deadline', 'End of next week')

    if not task:
        flash("No task provided to schedule.", 'error')
        return redirect(url_for('home'))

    try:
        service = build('calendar', 'v3', credentials=creds)

        event_date = datetime.date.today()
        if "today" in deadline_str.lower():
            event_date = datetime.date.today()
        elif "tomorrow" in deadline_str.lower():
            event_date = datetime.date.today() + datetime.timedelta(days=1)
        elif "friday" in deadline_str.lower():
            today_weekday = event_date.weekday()
            friday_weekday = 4
            days_until_friday = (friday_weekday - today_weekday + 7) % 7
            if days_until_friday == 0:
                days_until_friday = 7
            event_date += datetime.timedelta(days=days_until_friday)
        elif "next week" in deadline_str.lower():
            event_date += datetime.timedelta(weeks=1)
        else:
            event_date += datetime.timedelta(days=3)

        event = {
            'summary': f"{task} ({assignee})",
            'description': f"Action item from MeetingMind AI: {task} assigned to {assignee}. Suggested deadline: {deadline_str}.",
            'start': {
                'date': event_date.isoformat(),
                'timeZone': 'UTC',
            },
            'end': {
                'date': event_date.isoformat(),
                'timeZone': 'UTC',
            },
            'reminders': {
                'useDefault': False,
                'overrides': [
                    {'method': 'email', 'minutes': 24 * 60},
                    {'method': 'popup', 'minutes': 60},
                ],
            },
        }

        event = service.events().insert(calendarId='primary', body=event).execute()
        flash(f"Task '{task}' scheduled successfully in Google Calendar!", 'success')
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"Error scheduling task in Google Calendar: {e}", 'error')
        print(f"Google Calendar API error: {e}")
        return redirect(url_for('home'))


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, port=5000)