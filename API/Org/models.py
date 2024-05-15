from DB import db

class OrgModel(db.Model):
    __tablename__ = "organisation"

    org_id = db.Column(db.Integer, primary_key=True, unique=True)
    org_owner = db.Column(db.Integer, nullable=False)
    org_name = db.Column(db.String(80), nullable=False)
    admins = db.Column(db.String(1024), nullable=False)
    allow_endpoint_creation = db.Column(db.Boolean, default=True)
    allow_invites = db.Column(db.Boolean, default=True)
    limit = db.Column(db.BigInteger, default=100000)