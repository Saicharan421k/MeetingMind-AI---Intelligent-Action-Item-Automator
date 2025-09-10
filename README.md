# MeetingMind AI - Intelligent Action Item Automator

**Tagline:** Transform Meeting Notes into Trackable Tasks Automatically.

**Team Name:** [Your Team Name Here]
**Team Members:**
- [Your Name 1]
- [Your Name 2]
- [etc.]

---

### **Which hackathon theme / challenge was addressed:**
Theme 1: Build a purposeful AI agent.

### **What We Built + How to Run It:**

MeetingMind AI is a Flask-based web application designed to eliminate the common problem of untracked meeting action items. It acts as an intelligent assistant that takes raw meeting notes, processes them with advanced AI, extracts structured action items, and automatically schedules them into the user's Google Calendar.

**Core Features:**
1.  **Secure & Flexible User Authentication:** Powered by Descope, users can securely sign up and log in using:
    *   Magic Link (Email)
    *   Email and Password
    *   Social Logins (Google, Microsoft, GitHub)
    *   (Passkeys integrated as a placeholder for future client-side SDK integration)
2.  **AI-Powered Action Item Extraction:** Leverages Google Gemini 1.5 Flash to intelligently parse unstructured meeting notes and identify concrete tasks, assignees, and suggested deadlines.
3.  **Automated Google Calendar Scheduling:** Seamlessly connects with Google Calendar to create events for extracted action items, ensuring tasks are visible and trackable.
4.  **Modern User Interface:** A clean, intuitive, and responsive web interface for a smooth user experience.

**How to Run MeetingMind AI:**

1.  **Prerequisites:**
    *   Python 3.8+
    *   `pip` (Python package installer)
    *   Access to Descope Console, Google Cloud Console, Azure Portal (for Microsoft Social), GitHub account (for GitHub Social).

2.  **Clone the Repository:**
    ```bash
    git clone [Your GitHub Repo URL Here]
    cd MeetingMindAI
    ```

3.  **Set up Virtual Environment & Install Dependencies:**
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables (`.env` file):**
    *   Create a file named `.env` in the root of your project directory.
    *   Populate it with your credentials:
        ```
        # Descope Project Credentials
        DESCOPE_PROJECT_ID="P2XXXXXXXXX"
        DESCOPE_MANAGEMENT_KEY="K2XXXXXXXXX"

        # Google Gemini AI Key
        GOOGLE_API_KEY="AIzaSyXXXXXXXXXXXXXXXXXXXX"

        # Google Calendar API (Direct OAuth) Credentials
        # Create a NEW OAuth 2.0 Web Application client in Google Cloud Console for this.
        # Set its Authorized Redirect URI to: http://127.0.0.1:5000/google-calendar/callback
        GOOGLE_CLIENT_ID="YOUR_DIRECT_GOOGLE_CALENDAR_CLIENT_ID"
        GOOGLE_CLIENT_SECRET="YOUR_DIRECT_GOOGLE_CALENDAR_CLIENT_SECRET"
        ```
    *   **Descope Console Configuration (CRITICAL for Authentication):**
        *   **Login to Descope Console.**
        *   **Authentication Methods > Passwords:** Ensure "Email and Password" is Enabled.
        *   **Authentication Methods > Magic Link:**
            *   Ensure "Redirect URL" (under Advanced) is **EXACTLY `http://127.0.0.1:5000/auth/callback`**.
            *   Ensure "Auto-create user on sign-up" is enabled and policies allow new unverified emails to initiate the flow.
        *   **Social & Enterprise Logins > Google:**
            *   Configure "Authentication Account" to "Descope".
            *   **In your Google Cloud Console (for this Descope Social Login client):** Create an OAuth 2.0 Web Application Client. Set its "Authorized redirect URIs" to **`https://api.descope.com/oauth/callback`**.
        *   **Social & Enterprise Logins > Microsoft:**
            *   Configure "Authentication Account" to "Use my own account".
            *   Provide your Azure AD "Application (client) ID" and "Client secret value".
            *   **In your Azure Portal (for this Descope Social Login client):** Create an App Registration. Set its "Redirect URI (Web)" to **`https://api.descope.com/oauth/callback`**.
        *   **Social & Enterprise Logins > GitHub:**
            *   Configure "Authentication Account" to "Use my own account".
            *   Provide your GitHub OAuth App "Client ID" and "Client secret".
            *   **In your GitHub OAuth App settings:** Set its "Authorization callback URL" to **`https://api.descope.com/oauth/callback`**.
        *   **Authentication Methods > Passkeys (WebAuthn):** Ensure this is Enabled.

5.  **Run the Flask Application:**
    ```bash
    python app.py
    ```
6.  **Access the Application:** Open your web browser and go to `http://127.0.0.1:5000`.

### **Tech Stack Used:**
*   **Backend:** Python 3.x, Flask
*   **Authentication:** Descope (SDK v1.7.9) - Magic Link, Email+Password, Google/Microsoft/GitHub Social Login
*   **AI:** Google Gemini 1.5 Flash (via `google-generativeai`)
*   **Calendar Integration:** Google Calendar API (via `google-api-python-client`, `google-auth-oauthlib`)
*   **Environment Variables:** `python-dotenv`
*   **Frontend:** HTML, Custom CSS (modern design)

### **Demo Video Link:**
[Paste your YouTube/Vimeo/Youku video link here]

### **What We'd Do With More Time (Future Enhancements):**

1.  **Enhanced Meeting Integration (Google Meet Focus):**
    *   **Live Subtitle Capture & Auto-Extraction:** Integrate directly with Google Meet's API to capture live subtitles/transcripts, feeding this raw data automatically into the extraction field, rather than requiring manual pasting.
    *   **Real-time Calendar Updates:** Automatically update the event description in Google Calendar with the AI-extracted action items during or immediately after the meeting.
2.  **Advanced Storage & Organization:**
    *   **Google Drive Integration:** Enable users to store original meeting notes and AI-generated summaries directly in Google Drive, linking them to the calendar events.
    *   **Categorization & Project Management:** Implement features to categorize action items, assign them to projects, and integrate with dedicated project management tools (e.g., Asana, Trello).
3.  **Deeper AI & Personalization:**
    *   **Learning User Preferences:** The AI could learn preferred assignees for certain task types or common deadlines for specific projects.
    *   **Proactive Suggestions:** Suggest follow-up meetings or related resources based on extracted action items.
4.  **Client-Side Passkey Integration:** Fully implement Passkey registration and login flows using Descope's client-side JavaScript SDK for a truly passwordless experience.
5.  **User Settings & Customization:** Allow users to define default calendars, reminder preferences, and AI extraction parameters.

---

#### **Source code (Upload file):**
**(Instructions for you):**
*   Zip your entire project folder (`MeetingMindAI/`).
*   Upload the `.zip` file here.

---

**Final Check:** Remember to thoroughly test **all** authentication methods one last time after making these final changes and before submitting! The "unverified email" on Magic Link signup is the only remaining known minor issue, and it's framed well in the submission text as a policy configuration detail.

Good luck with your submission – you've built an impressive project!
