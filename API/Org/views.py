import uuid
from flask import request, jsonify
from flask_smorest import Blueprint, abort
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.exc import SQLAlchemyError
from API.Auth.service import invite_user
import json
import bcrypt
import time
import string
import random
from config import config

from DB import db
from API.Auth.models import UserModel
from API.Org.models import OrgModel

blp = Blueprint("organisations", __name__, description="Operations on organisations")

@blp.route('/get_org', methods=['POST'])
@jwt_required()
def endpoints_get_organisation():
    """
       Returns organisations endpoints
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned json of organisations endpoints.
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
    members = UserModel.query.filter(UserModel.org_id == org.org_id).all()

    admins = json.loads(org.admins)

    organisation_data = []

    for member in members:
        dict_user = {
            "id": member.id,
            "email": member.email,
            "name": f"{member.first_name} {member.last_name}",
            "role": "admin" if member.id in admins else "member",
            "date_joined": member.date_created.strftime("%Y-%m-%d %H:%M:%S")  # Format date as string
        }
        organisation_data.append(dict_user)

    return organisation_data

@blp.route('/get_limit', methods=['POST'])
@jwt_required()
def get_organisation_limit():
    """
       Returns organisations limit
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned organisations usage limit
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    return jsonify(org.limit)

@blp.route('/invite', methods=['POST'])
@jwt_required()
def add_to_organisation():
    """
    Register a new user.

    ---
    tags:
      - Organisation
    parameters:
      - in: body
        name: user
        description: User registration details.
        required: true
        schema:
          type: object
          required:
            - email
            - first_name
            - last_name
          properties:
            email:
              type: string
              format: email
              example: user@example.com
            first_name:
              type: string
              example: john
            last_name:
              type: string
              example: Doe
    responses:
      201:
        description: User registered successfully.
      400:
        description: Invalid data or user already exists.
    """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    user_data = request.get_json()

    if UserModel.query.filter(UserModel.email == user_data["email"]).first():
        abort(409, message="User has already registered")

    reset_password_token = str(uuid.uuid4())

    characters = string.ascii_uppercase + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(20))

    userToAdd = UserModel(
        email=user_data["email"],
        first_name=user_data["first_name"],
        last_name=user_data["last_name"],
        password=bcrypt.hashpw(random_string.encode('utf-8'), bcrypt.gensalt()), #Generate a strong random password as they may decide to login with gauth
        role="user",
        reset_password_token=reset_password_token,
        org_name=user.org_name,
        org_id=user.org_id
    )

    db.session.add(userToAdd)
    db.session.commit()

    reset_link = f"{config.Config.FRONTEND_URL}/reset-password/{user.reset_password_token}"

    invite_user(user_data["email"], user.org_name, user.first_name + " " + user.last_name, reset_link)

    return jsonify({"message": "An invite email has been sent"}), 200

@blp.route('/resend-invite', methods=['POST'])
@jwt_required()
def resend_invite():
    """
    Resend invite email.
    ---
    tags:
      - Organisation
    parameters:
      - in: body
        name: user
        description: User email details.
        required: true
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
              format: email
              example: user@example.com
    responses:
      200:
        description: Invite email resent successfully.
      400:
        description: Invalid data or user not found.
    """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)
    user_data = request.get_json()
    
    email = user_data.get('email')
    user_to_invite = UserModel.query.filter_by(email=email).first()
    if not user_to_invite:
        return jsonify({"message": "If an account with that email exists, an invite email has been resent."}), 200

    if (int(user_to_invite.unix_time_of_email) + 60) > int(time.time()):
        return jsonify({"message": "Please wait to resend email"}), 429

    reset_password_token = str(uuid.uuid4())
    user_to_invite.reset_password_token = reset_password_token
    user_to_invite.unix_time_of_email = str(int(time.time()))
    db.session.commit()

    reset_link = f"{config.Config.FRONTEND_URL}/invite/{user_to_invite.reset_password_token}"
    invite_user(user_data["email"], user.org_name, user.first_name + " " + user.last_name, reset_link)

    return jsonify({"message": "If an account with that email exists, an invite email has been resent."}), 200

@blp.route('/make_admin', methods=['POST'])
@jwt_required()
def make_admin():
    """
    Make a user an Admin.

    ---
    tags:
      - Organisation
    parameters:
      - in: body
        name: user
        description: User registration details.
        required: true
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
              format: email
              example: user@example.com
    responses:
      200:
        description: Admin list updated
      400:
        description: You are not an admin
    """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
    admins = json.loads(org.admins)

    if user.id not in admins:
        abort(409, message="You are not an admin of your org")

    user_data = request.get_json()
    user_to_add = UserModel.query.filter(UserModel.email == user_data["email"]).first()

    if user_to_add.org_id == user.org_id:
        admins.append(user_to_add.id)
        org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
        org.admins = json.dumps(admins)
        db.session.commit()
    else:
        abort(409, message="This user is not part of your organisation")

    return jsonify({"message": "Admins updated"}), 200

@blp.route('/is_admin', methods=['POST'])
@jwt_required()
def is_admin():
    """
       Checks if the current user is an admin of their org
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    admins = json.loads(org.admins)

    return jsonify({"is_admin": user.id in admins}), 200


@blp.route('/disable_endpoint_creation', methods=['POST'])
@jwt_required()
def disable_endpoint_creation():
    """
       Disables none admin users from creating an endpoint
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    admins = json.loads(org.admins)

    if user.id in admins:
        org.allow_endpoint_creation = False
        db.session.commit()
    else:
        abort(409, message="Only Admins can do this")

    return jsonify({"message": "Non admins can no longer create endpoints"}), 200

@blp.route('/enable_endpoint_creation', methods=['POST'])
@jwt_required()
def enable_endpoint_creation():
    """
       Allow none admin users from creating an endpoint
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    admins = json.loads(org.admins)

    if user.id in admins:
        org.allow_endpoint_creation = True
        db.session.commit()
    else:
        abort(409, message="Only Admins can do this")

    return jsonify({"message": "Non admins can now create endpoints"}), 200

@blp.route('/can_create_endpoints', methods=['POST'])
@jwt_required()
def can_create_endpoints():
    """
       Check if non-admin user can create endpoints
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    return jsonify({"can_create_endpoints": org.allow_endpoint_creation}), 200

@blp.route('/disable_invite', methods=['POST'])
@jwt_required()
def disable_invite():
    """
       Disables none admin users from inviting users
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    admins = json.loads(org.admins)

    if user.id in admins:
        org.allow_invites = False
        db.session.commit()
    else:
        abort(409, message="Only Admins can do this")

    return jsonify({"message": "Non admins can no longer invite users"}), 200

@blp.route('/enable_invite', methods=['POST'])
@jwt_required()
def enable_invite():
    """
       Allow none admin users to invite users
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    admins = json.loads(org.admins)

    if user.id in admins:
        org.allow_invites = True
        db.session.commit()
    else:
        abort(409, message="Only Admins can do this")

    return jsonify({"message": "Non admins can now invite users"}), 200

@blp.route('/can_invite', methods=['POST'])
@jwt_required()
def can_invite():
    """
       Check if non-admin user can invite users
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned admin status
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    return jsonify({"can_invite": org.allow_invites}), 200


@blp.route('/get_my_org_name', methods=['POST'])
@jwt_required()
def get_my_org_name():
    """
       Retrieve the name of the organization associated with the current user.
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
       responses:
         200:
           description: JSON object containing the organization name
         404:
           description: Organization not found or user not associated with any organization
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)
    if user and user.org_id:
        org = OrgModel.query.get(user.org_id)
        if org:
            return jsonify({"org_name": org.org_name}), 200
    abort(404, message="Organization not found or user not associated with any organization")

@blp.route('/edit_my_org_name', methods=['POST'])
@jwt_required()
def edit_my_org_name():
    """
       Allows an admin user to edit the name of their associated organization.
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
         - in: body
           name: body
           description: JSON object containing the new organization name
           required: true
           schema:
             type: object
             properties:
               org_name:
                 type: string
                 example: "New Org Name"
       responses:
         200:
           description: Organization name updated successfully
         400:
           description: No new organization name provided
         403:
           description: User is not authorized to edit this organization
         404:
           description: Organization not found or user not associated with any organization
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)
    if not user or not user.org_id:
        abort(404, message="Organization not found or user not associated with any organization")

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()
    admins = json.loads(org.admins)
    is_admin = user.id in admins

    if not is_admin:
        abort(403, message="User is not authorized to edit this organization")

    data = request.get_json()
    new_name = data.get("org_name")
    if new_name:
        org.org_name = new_name
        db.session.commit()
        return jsonify({"message": "Organization name updated successfully"}), 200
    else:
        abort(400, message="No new organization name provided")

@blp.route('/edit_my_details', methods=['POST'])
@jwt_required()
def edit_my_details():
    """
    Allows a user to edit their own first name and last name.
    ---
    tags:
      - Users
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
      - in: body
        name: body
        description: JSON object containing the new user details.
        required: true
        schema:
          type: object
          properties:
            first_name:
              type: string
              example: John
            last_name:
              type: string
              example: Doe
    responses:
      200:
        description: User details updated successfully.
      400:
        description: Invalid data provided.
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)

    data = request.get_json()
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']

    db.session.commit()
    return jsonify({"message": "Your details have been updated successfully."}), 200

@blp.route('/edit_user_details', methods=['POST'])
@jwt_required()
def edit_user_details_by_email():
    """
    Allows an admin to edit the first name, last name, or email of a user within the same organization.
    ---
    tags:
      - Users
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
      - in: body
        name: body
        description: JSON object containing the user details to be edited along with the target email.
        required: true
        schema:
          type: object
          required:
            - target_email
          properties:
            target_email:
              type: string
              example: user@example.com
            first_name:
              type: string
              example: Jane
            last_name:
              type: string
              example: Doe
            email:
              type: string
              format: email
              example: newuser@example.com
    responses:
      200:
        description: User details updated successfully.
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "User details updated successfully."
      400:
        description: Failed to update user details due to invalid input or database error.
      403:
        description: Insufficient permissions to edit user or users are not in the same organization.
      404:
        description: User not found.
    """
    current_user_id = get_jwt_identity()
    current_user = UserModel.query.get(current_user_id)
    
    data = request.get_json()
    target_email = data.get('target_email')
    target_user = UserModel.query.filter_by(email=target_email).first()

    if not target_user:
        abort(404, message="User not found.")
    
    org = OrgModel.query.get(current_user.org_id)
    if org is None or target_user.org_id != org.org_id:
        abort(403, message="Users are not in the same organization.")
    
    admins = json.loads(org.admins)
    if current_user.id not in admins:
        abort(403, message="Insufficient permissions to edit user.")
    if target_user.role != 'user':
        abort(403, message="Insufficient permissions to edit user.")

    if 'email' in data:
        target_user.email = data['email']
    if 'first_name' in data:
        target_user.first_name = data['first_name']
    if 'last_name' in data:
        target_user.last_name = data['last_name']

    try:
        db.session.commit()
        return jsonify({"message": "User details updated successfully."}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        abort(400, message="Failed to update user details due to database error.")

@blp.route('/my_details', methods=['POST'])
@jwt_required()
def get_my_details():
    """
    Retrieves the current logged-in user's details such as email, first name, and last name.
    ---
    tags:
      - Users
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
    responses:
      200:
        description: Returns the logged-in user's details.
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                first_name:
                  type: string
                last_name:
                  type: string
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)
    if not user:
        abort(404, message="User not found.")

    user_details = {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name
    }
    return jsonify(user_details), 200

@blp.route('/get_org_name', methods=['POST'])
@jwt_required()
def get_organisation_name():
    """
       Returns the organisation name
       ---
       tags:
            - Organisation
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned organisation name
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    if not org:
        abort(404, message="Organisation not found")

    return jsonify(org.org_name)

@blp.route('/update_org_name', methods=['POST'])
@jwt_required()
def update_org_name():
    """
    Update the organisation name.
    ---
    tags:
      - Organisation
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
      - in: body
        name: org
        description: Organisation name update details.
        required: true
        schema:
          type: object
          required:
            - new_org_name
          properties:
            new_org_name:
              type: string
              example: New Organisation Name
    responses:
      200:
        description: Organisation name updated successfully.
      400:
        description: Invalid data or unauthorized action.
    """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    if not user:
        abort(401, message="User not found")

    org = OrgModel.query.filter(OrgModel.org_id == user.org_id).first()

    if not org:
        abort(404, message="Organisation not found")

    admins = json.loads(org.admins)
    if user.id not in admins:
        abort(403, message="User is not an admin")

    new_org_name = request.json.get("new_org_name")
    if not new_org_name:
        abort(400, message="New organisation name is required")

    try:
        org.org_name = new_org_name
        db.session.commit()
        return jsonify({"message": "Organisation name updated successfully"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        abort(500, message="An error occurred while updating the organisation name")
