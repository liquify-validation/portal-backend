from DB import db
from datetime import datetime, timezone


class APIKeyModel(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(255), nullable=False)
    chain_id = db.Column(db.Integer, db.ForeignKey('chains.id'), nullable=False)
    chain_name = db.Column(db.String(255),nullable=False)
    chain = db.relationship('ChainsModel', backref=db.backref('api_keys', lazy=True))
    api_key = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, nullable=False)
    org_id = db.Column(db.Integer, nullable=True)
    org_name = db.Column(db.String(255), nullable=True)
    routing = db.Column(db.String(40), nullable=True, default="pokt")
    limit = db.Column(db.BigInteger, default=0)
