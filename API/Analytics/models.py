from DB import db
from datetime import datetime, timezone

class AnalyticsModel(db.Model):
    __tablename__ = "analytics_cache"

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(20), unique=False, nullable=True)
    org = db.Column(db.Integer, nullable=True)
    date = db.Column(db.String(16), nullable=False)
    success = db.Column(db.Integer, nullable=False)
    errors = db.Column(db.Integer, nullable=False)
    finalised = db.Column(db.Boolean, default=False)