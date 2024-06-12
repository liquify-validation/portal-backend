from flask import Blueprint, redirect, url_for, jsonify, session, request
import logging
from config import config
from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import create_access_token, create_refresh_token
from API.Auth.models import UserModel
from API.Org.models import OrgModel
from DB import db
import string
import random
import bcrypt
import json
import os

oauth = OAuth()

logger = logging.getLogger(__name__)

def setup_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='github',
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        authorize_url="https://github.com/login/oauth/authorize",
        authorize_params=None,
        access_token_url="https://github.com/login/oauth/access_token",
        access_token_params=None,
        client_kwargs={'scope': 'user user:email'},
        api_base_url="https://api.github.com/"
    )

github_auth_blp = Blueprint('github_auth', __name__)

@github_auth_blp.route('/login/github')
def github_login():
    redirect_uri = url_for('github_auth.github_callback', _external=True, _scheme='https')
    return oauth.github.authorize_redirect(redirect_uri)

@github_auth_blp.route('/callback/github')
def github_callback():
    try:
        token = oauth.github.authorize_access_token()
        if token is None:
            return jsonify({"error": "Failed to retrieve access token"}), 400

        oauth.github.token = token
        resp = oauth.github.get('user')
        profile = resp.json()


        if not profile:
            return jsonify({"error": "Failed to retrieve user profile"}), 400

        email_resp = oauth.github.get('user/emails')
        email_data = email_resp.json()

        if not email_data:
            return jsonify({"error": "Failed to retrieve email data"}), 400

        email = next((email['email'] for email in email_data if email['primary']), None)
        if not email:
            return jsonify({"error": "Primary email not found"}), 400

        user = UserModel.query.filter_by(email=email).first()

        if not user:
            random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            hashed_password = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt())

            # Handle cases where the name field is None or empty
            name = profile.get('name', '')
            if name:
                name_parts = name.split()
                first_name = name_parts[0] if len(name_parts) > 0 else ''
                last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
            else:
                first_name = ''
                last_name = ''

            user = UserModel(
                email=email,
                first_name=first_name,
                last_name=last_name,
                role="user",
                is_email_verified=True,
                mfa_enabled=False,
                password=hashed_password,
            )
            db.session.add(user)
            db.session.commit()

            org = OrgModel(
                org_owner=user.id,
                org_name=email,
                admins=json.dumps([user.id])
            )
            db.session.add(org)
            db.session.commit()
            user.org_id = org.org_id
            user.org_name = org.org_name
            db.session.commit()

        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)

        redirect_url = f'{config.Config.FRONTEND_URL}/auth/callback'
        return redirect(f"{redirect_url}?access_token={access_token}&refresh_token={refresh_token}&user_id={user.id}")

    except Exception as e:
        return jsonify({"error": str(e)}), 400