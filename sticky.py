from flask import Flask, redirect, request, session, jsonify
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Discord configuration
CLIENT_ID = "1391860994082472009"
CLIENT_SECRET = "q5PD-1vYrbJl_1cmZTzwm-_PDqNBJy6q"
REDIRECT_URI = "http://localhost:5000/callback"
API_BASE_URL = "https://discord.com/api/v10"
GUILD_ID = "1391817979754319902"
BOT_TOKEN = "MTM5MjU3NTcwNjcwNTQyODYwMg.GCkoPh.8frtokLNmJmoW5YO9k1cAhAtJ5AKrE3EASbvlw"


@app.route('/')
def home():
    return '<a href="/login">Login with Discord</a>'

@app.route('/login')
def login():
    # Generate the Discord OAuth2 authorization URL
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify%20guilds"
    )
    return redirect(discord_auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    # Exchange the authorization code for an access token
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    response = requests.post(f'{API_BASE_URL}/oauth2/token', data=data, headers=headers)
    credentials = response.json()
    access_token = credentials['access_token']
    
    # Get the logged-in user's info
    user_headers = {
        'Authorization': f'Bearer {access_token}'
    }
    user_response = requests.get(f'{API_BASE_URL}/users/@me', headers=user_headers)
    user = user_response.json()
    user_id = user['id']
    
    # Get the user's member data in the guild
    bot_headers = {
        'Authorization': f'Bot {BOT_TOKEN}'
    }
    member_response = requests.get(f'{API_BASE_URL}/guilds/{GUILD_ID}/members/{user_id}', headers=bot_headers)
    if member_response.status_code == 200:
        member = member_response.json()
        return jsonify({'roles': member['roles']})
    else:
        return jsonify({'error': f"Unable to fetch member roles: {member_response.status_code}"})

if __name__ == '__main__':
    app.run(debug=True)