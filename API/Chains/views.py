from flask import request, jsonify
from flask.views import MethodView

from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import jwt_required, get_jwt

from DB import db
from DB.schemas import ChainsSchema
from API.Chains.models import ChainsModel

blp = Blueprint("chains", __name__, description="Operations on chains")


@blp.route("/chains")
class Chains(MethodView):

    @blp.response(200, ChainsSchema(many=True))
    def get(self):
        return ChainsModel.query.all()

    @jwt_required()
    @blp.arguments(ChainsSchema)
    @blp.response(201, ChainsSchema)
    def post(self, chain_data):
        claims = get_jwt()
        if claims["role"] != "superadmin":
            abort(403, message="Insufficient permissions")
        if ChainsModel.query.filter(ChainsModel.name == chain_data["name"]).first():
            abort(400, message="A chain with that name already exists")

        chain = ChainsModel(**chain_data)

        try:
            db.session.add(chain)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message=str(e))

        return chain


@blp.route("/chains/<int:chain_id>")
class Chain(MethodView):

    @jwt_required()
    def delete(self, chain_id):
        claims = get_jwt()
        if claims["role"] != "superadmin":
            abort(403, message="Insufficient permissions")
        chain = ChainsModel.query.get_or_404(chain_id)

        try:
            db.session.delete(chain)
            db.session.commit()
            return {"message": "Chain Deleted."}, 200
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message=str(e))


@blp.route("/chains/<int:chain_id>")
class ChainNameUpdate(MethodView):

    @jwt_required()
    def patch(self, chain_id):
        claims = get_jwt()
        if claims["role"] != "superadmin":
            abort(403, message="Insufficient permissions")

        chain = ChainsModel.query.get_or_404(chain_id)
        json_data = request.get_json()

        if 'name' in json_data:
            new_name = json_data['name']
            if ChainsModel.query.filter(ChainsModel.name == new_name).first():
                abort(400, message="A chain with that name already exists")

            chain.name = new_name

            try:
                db.session.commit()
                return jsonify({"message": "Chain name updated successfully"}), 200
            except SQLAlchemyError as e:
                db.session.rollback()
                abort(500, message=str(e))
        else:
            abort(400, message="No name provided")
