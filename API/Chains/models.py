from DB import db
from datetime import datetime, timezone


class ChainsModel(db.Model):
    __tablename__ = "chains"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    routing = db.Column(db.String(1024), default="[pokt]")