from flask import Flask, request, redirect, session, url_for, jsonify
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/userinfo.email"]

@app.route('/')
def index():
    return '✅ Smart Email Sender Backend Running! Visit /login to authorize.'

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    session['user_email'] = user_info['email']

    return f"✅ Authorized as: {session['user_email']}<br><br><a href='/send_test'>Send Test Email</a>"

def send_email(user_id, creds_dict, to_email, subject, message_text):
    creds = Credentials(**creds_dict)
    service = build('gmail', 'v1', credentials=creds)

    message = MIMEText(message_text)
    message['to'] = to_email
    message['from'] = user_id
    message['subject'] = subject

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw}

    try:
        sent_msg = service.users().messages().send(userId='me', body=body).execute()
        return {'messageId': sent_msg['id']}
    except Exception as e:
        return {'error': str(e)}

@app.route('/send_test')
def send_test():
    if 'credentials' not in session:
        return redirect('/login')
    result = send_email(
        user_id=session['user_email'],
        creds_dict=session['credentials'],
        to_email=session['user_email'],
        subject='Smart Email Sender Test',
        message_text='Hello from Smart Email Sender backend! ✅'
    )
    return jsonify(result)

@app.route('/send_emails', methods=['POST'])
def send_emails():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 403

    data = request.json
    emails = data.get('emails', [])
    subject = data.get('subject', 'Smart Email Sender')
    message = data.get('message', '')
    schedule_time = data.get('schedule')

    print(f"🕒 Schedule time received: {schedule_time}")  # Log schedule

    results = []
    for entry in emails:
        to_email = entry['email']
        name = entry.get('name', '')
        personalized_message = message.replace('{First Name}', name or 'there')

        print(f"Sending to: {to_email}")
        print(f"Message: {personalized_message}")

        result = send_email(
            user_id=session['user_email'],
            creds_dict=session['credentials'],
            to_email=to_email,
            subject=subject,
            message_text=personalized_message
        )

        print(result)
        results.append({'to': to_email, 'result': result})

    return jsonify({'status': 'done', 'results': results, 'schedule': schedule_time})

if __name__ == '__main__':
    app.run(debug=True)
