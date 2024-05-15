from marshmallow import ValidationError
from config import config
from flask import request, redirect, url_for, Blueprint, jsonify, Flask
from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from DB import db
from API.Auth.models import UserModel
import string
import random
import bcrypt
from API.Org.models import OrgModel
import json
import os

oauth = OAuth()

def setup_oauth(app: Flask):
    global oauth 
    oauth.init_app(app)

    oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)
    
google_auth_blp = Blueprint('google_auth', __name__)


@google_auth_blp.route('/google-login')
def google_login():
    redirect_uri = url_for('.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@google_auth_blp.route('/signin-google')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        print(e)  # Properly log the error
        return redirect(f'{config.Config.FRONTEND_URL}/error')

    data = oauth.google.get('https://www.googleapis.com/oauth2/v2/userinfo').json()

    user = UserModel.query.filter_by(email=data['email']).first()

    if not user:
        # Generate a random 20character password because it can't be null
        characters = string.ascii_uppercase + string.digits
        random_string = ''.join(random.choice(characters) for _ in range(20))

        user = UserModel(
            email=data['email'],
            first_name=data['given_name'] if 'given_name' in data else '',
            last_name=data['family_name'] if 'family_name' in data else '',
            role="user",
            is_email_verified=data['verified_email'] if 'verified_email' in data else False,
            mfa_enabled=False,
            password=bcrypt.hashpw(random_string.encode('utf-8'), bcrypt.gensalt()),
        )
        db.session.add(user)
        db.session.commit()

        # make them an org - name it with email (they can change it later)
        admins = [user.id]
        org = OrgModel(
            org_owner=user.id,
            org_name=data['email'],
            admins=json.dumps(admins)
        )
        db.session.add(org)
        db.session.commit()
        org_id = org.org_id
        org_name = org.org_name

        user = UserModel.query.filter(UserModel.email == data['email']).first()
        user.org_id = org_id
        user.org_name = org_name
        db.session.commit()

    access_token = create_access_token(identity=user.id, fresh=True)
    refresh_token = create_refresh_token(identity=user.id)

    # Instead of redirecting with cookies, return the tokens directly
    tokens = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    # Assuming you have a frontend route ready to handle these tokens
    redirect_url = f'{config.Config.FRONTEND_URL}/home_with_tokens'
    test=f"{redirect_url}?access_token={tokens['access_token']}&refresh_token={tokens['refresh_token']}"

    return redirect(f"{redirect_url}?access_token={tokens['access_token']}&refresh_token={tokens['refresh_token']}")


@google_auth_blp.route('/status', methods=['GET'])
@jwt_required()
def auth_status():
    print(request.headers)
    # The jwt_required decorator ensures that this point is reached only if
    # a valid JWT token is present in the request headers.
    current_user_id = get_jwt_identity()  # Get the user ID from the token.
    user = UserModel.query.get(current_user_id)
    
    if user:
        # If a user is found with the ID in the token, they are considered authenticated.
        return jsonify({'isAuthenticated': True, 'userId': current_user_id, 'email': user.email}), 200
    else:
        # This should theoretically never happen if your token management is secure,
        # but it's good to handle the case.
        return jsonify({'isAuthenticated': False}), 404