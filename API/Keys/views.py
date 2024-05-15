from flask import jsonify
from flask.views import MethodView
import string
import secrets
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask import request

from DB import db
from DB.schemas import APIKeySchema
from API.Chains.models import ChainsModel
from API.Keys.models import APIKeyModel
from API.Auth import UserModel
from API.Org import OrgModel

import json

blp = Blueprint("api_keys", __name__, description="Operations on API keys")

@blp.route("/key")
class APIKey(MethodView):

    @jwt_required()
    def post(self):
        """
           Create a new API key for a gievn chain
           ---
           tags:
                - Key
           parameters:
             - in: header
               name: Authorization
               description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
             - in: body
               name: body
               description: Use reset token to reset password
               required: true
               schema:
                 type: object
                 required:
                   - chain_name
                   - api_name
                 properties:
                   chain_name:
                     type: string
                   api_name:
                     type: string
           responses:
             200:
               description: Password reset successful.
             400:
               description: Password reset failed.
           """

        # Lookup the chain by name
        api_key_data = request.get_json()
        chain = ChainsModel.query.filter_by(name=api_key_data["chain_name"]).first()
        if not chain:
            abort(404, message="Chain not found")

        current_user = get_jwt_identity()
        user = UserModel.query.get(current_user)
        org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
        admins = json.loads(org.admins)

        if (user.id not in admins) and (not org.allow_endpoint_creation):
            abort(401, message="You do not have permission to create endpoints")

        api_names = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_name).all()
        api_names_list = [api_name for api_name, in api_names]

        if api_key_data["api_name"] in api_names_list:
            abort(500, message="You already have a key with this name")

        generated_key = None
        characters = string.ascii_uppercase + string.digits
        while True:
            generated_key = ''.join(secrets.choice(characters) for _ in range(16))
            if not APIKeyModel.query.filter_by(api_key=generated_key).first():
                break

        generated_key = chain.name.upper() + generated_key

        limit = org.limit
        if "limit" in api_key_data:
            limit = api_key_data["limit"]
            if org.limit != 0 and int(limit) == 0:
                limit = org.limit
            if limit > org.limit:
                limit = org.limit

        api_key = APIKeyModel(
            api_name=api_key_data["api_name"],
            chain_id=chain.id,
            chain_name=chain.name,
            api_key=generated_key,
            org_id=user.org_id,
            org_name=user.org_name,
            user_id=current_user,
            limit=limit
        )

        try:
            db.session.add(api_key)
            db.session.commit()
            return jsonify(api_key.api_key)
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message=str(e))

    @jwt_required()
    def delete(self):
        """
        Delete a given API key
        ---
        tags:
          - Key
        parameters:
          - in: header
            name: Authorization
            description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
          - in: query
            name: api_key
            type: string
            required: true
            description: API key to delete
        responses:
          200:
            description: API Key deleted successfully
          404:
            description: API Key not found or deletion failed
        """
        current_user = get_jwt_identity()
        api_key = request.args.get("api_key")
        user = UserModel.query.get(current_user)

        org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
        admins = json.loads(org.admins)

        if not api_key:
            abort(400, message="API key is required")

        # Find the API key based on the provided key and user ID
        api_key_obj = APIKeyModel.query.filter_by(api_key=api_key, org_id=user.org_id).first()
        if not api_key_obj:
            abort(404, message="API Key not found or deletion failed")

        if api_key_obj.user_id == user.id or user.id in admins:
            try:
                db.session.delete(api_key_obj)
                db.session.commit()
                return {"message": "API Key deleted successfully"}, 200
            except SQLAlchemyError as e:
                db.session.rollback()
                abort(500, message=str(e))
        else:
            abort(404, message="You don't have permission to delete this key")

@blp.route('/set_limit', methods=['POST'])
@jwt_required()
def set_key_limit():
    """
    Set the limit for a specified API key
    ---
    tags:
      - Key
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
      - in: query
        name: api_key
        type: string
        required: true
        description: API key to which the limit is to be set
      - in: query
        name: limit
        type: integer
        required: true
        description: New limit value to be set for the API key
    responses:
      200:
        description: API Key limit set successfully
      400:
        description: API key and/or limit is required
      404:
        description: API Key not found or user does not have permission to set limit
      500:
        description: Internal server error, details in error message
    """
    current_user = get_jwt_identity()
    api_key = request.args.get("api_key")
    limit = request.args.get("limit")
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
    admins = json.loads(org.admins)

    if not api_key or not limit:
        abort(400, message="API key and limit is required")

    if int(limit) > org.limit:
        abort(400, message="You are trying to set above your orgs usage limit")

    if int(limit) < 0:
        abort(400, message="Limit must be a positive integer")

    if org.limit != 0 and int(limit) == 0:
        limit = org.limit

    # Find the API key based on the provided key and user ID
    api_key_obj = APIKeyModel.query.filter_by(api_key=api_key, org_id=user.org_id).first()
    if not api_key_obj:
        abort(404, message="API Key not found")

    if api_key_obj.user_id == user.id or user.id in admins:
        try:
            api_key_obj.limit = limit
            db.session.commit()
            return {"message": "API Key limit set successfully"}, 200
        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message=str(e))
    else:
        abort(404, message="You don't have permission to set the limit for this key")



@blp.route("/keys")
class APIKeys(MethodView):
    @jwt_required()
    @blp.response(200, APIKeySchema(many=True))
    def get(self):
        """
           Returns all API key for the authorised user
           ---
           tags:
                - Keys
           parameters:
             - in: header
               name: Authorization
               description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
           responses:
             200:
               description: all returned chains are passed back
           """
        current_user = get_jwt_identity()
        user = UserModel.query.get(current_user)
        api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_name, APIKeyModel.api_key, APIKeyModel.chain_name, APIKeyModel.date_created, APIKeyModel.limit)
        return api_keys