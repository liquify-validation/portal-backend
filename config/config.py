import os
from urllib.parse import quote_plus
from datetime import timedelta

class Config:
    DB_USERNAME = os.getenv('DATABASE_USERNAME')
    DB_PASSWORD = os.getenv('DATABASE_PASSWORD')
    DB_HOST = os.getenv('DATABASE_HOST')
    DB_PORT = os.getenv('DATABASE_PORT')
    FRONTEND_URL = os.getenv('FRONTEND_URL')
    MAILGUN_API = os.getenv('MAILGUN_API_KEY')
    EMAIL_FROM = os.getenv('EMAIL_FROM')

    encoded_username = quote_plus(DB_USERNAME)
    encoded_password = quote_plus(DB_PASSWORD)

    PROPOGATE_EXCEPTIONS = True
    API_TITLE = "Portal Auth"
    API_VERSION = "v1"
    OPENAPI_VERSION = "3.0.3"
    OPENAPI_URL_PREFIX = "/"
    OPENAPI_SWAGGER_UI_PATH = "/docs"
    OPENAPI_SWAGGER_UI_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist"
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{encoded_username}:{encoded_password}@{DB_HOST}:{DB_PORT}/portal"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
