from DB import db
from datetime import datetime, timezone

class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    mfa_secret = db.Column(db.String(80), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(36), nullable=True)
    reset_password_token = db.Column(db.String(36), nullable=True)
    org_id = db.Column(db.Integer, nullable=True)
    org_name = db.Column(db.String(80), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    preference = db.Column(db.String(4096), nullable=True)
    unix_time_of_email = db.Column(db.String(80), nullable=True, default="0")

class BetaModel(db.Model):
    __tablename__ = "beta"

    email = db.Column(db.String(255), primary_key=True,unique=True, nullable=False)
