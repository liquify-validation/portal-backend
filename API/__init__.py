import os
from flask import Flask, jsonify, redirect
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from passlib.hash import pbkdf2_sha256
from flask_cors import CORS, cross_origin
from flasgger import Swagger
from flaskTemplate import template as flaskTemplate
from flaskTemplate import swagger_config as swaggerConfig
from authlib.integrations.flask_client import OAuth
from resources.googleAuth import setup_oauth as setup_google_oauth, google_auth_blp
from resources.githubAuth import setup_oauth as setup_github_oauth, github_auth_blp


from blocklist import BLOCKLIST
from urllib.parse import quote_plus
from dotenv import load_dotenv
load_dotenv()

from API.Auth import UsersBlueprint, UserModel
from API.Chains import ChainsBlueprint, ChainsModel
from API.Keys import APIKeysBlueprint, APIKeyModel
from API.Analytics import AnalyticsBlueprint, AnalyticsModel
from API.Org import OrgModel, OrgBlueprint

from config import config


def create_flask_app(db,db_url=None):
    app = Flask(__name__)
    swagger = Swagger(app, template=flaskTemplate, config=swaggerConfig)
    CORS(app)

    setup_google_oauth(app)
    setup_github_oauth(app)
    app.config.from_object(config.Config)
    db.init_app(app)

    api = Api(app)

    jwt = JWTManager(app)

    # Add blocklist to a database section or redis
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description": "The token has been revoked.", "error": "token_revoked"}
            ), 401
        )

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        user = UserModel.query.get(identity)
        if user:
            return {"role": user.role}
        return {"role": "user"}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}), 401
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify({"message": "signature verification failed.", "error": "invalid_token"}), 401
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
        jsonify({"description": "Request does not contain an access token.", "error": "authorization_required"}), 401)

    with app.app_context():
        db.create_all()

    app.register_blueprint(google_auth_blp, url_prefix='/auth')
    app.register_blueprint(github_auth_blp, url_prefix='/auth')
    api.register_blueprint(UsersBlueprint, url_prefix='/auth')
    api.register_blueprint(ChainsBlueprint, url_prefix='/chains')
    api.register_blueprint(APIKeysBlueprint, url_prefix='/access')
    api.register_blueprint(AnalyticsBlueprint, url_prefix='/analytics')
    api.register_blueprint(OrgBlueprint, url_prefix='/organisation')

    return app