import uuid
from flask import request, jsonify, url_for, redirect
from flask.views import MethodView
import pyotp
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from config import config
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
import json
import bcrypt

from DB import db
from blocklist import BLOCKLIST
from DB.schemas import UserSchema, UserLoginSchema, PasswordChangeSchema
from API.Auth.models import UserModel, BetaModel
from API.Org.models import OrgModel

from API.Auth.service import send_password_reset_email, send_verification_email

blp = Blueprint("users", __name__, description="Operations on users")
BETA = True


@blp.route("/user/<int:user_id>")
class Users(MethodView):
    @blp.response(200, UserSchema)  # working
    @jwt_required()
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    @jwt_required()
    def delete(self, user_id):
        claims = get_jwt()
        user_role = claims.get("role")

        user_to_delete = UserModel.query.get_or_404(user_id)

        if user_role == "user":
            abort(403, message="Insufficient permissions")
        elif user_role == "admin" and user_to_delete.role != "user":
            abort(403, message="Insufficient permissions")
        elif user_role in ["superadmin", "admin"]:
            db.session.delete(user_to_delete)
            db.session.commit()
            return {"message": "User successfully deleted"}
        else:
            abort(403, message="Insufficient permissions")


@blp.route("/register", methods=["POST"])
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        Register a new user.

        ---
        tags:
          - Authentication
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
                - password
                - org_name
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
                password:
                  type: string
                  example: password123
                org_name:
                  type: string
                  example: My Organisation
        responses:
          201:
            description: User registered successfully.
          400:
            description: Invalid data or user already exists.
        """

        if UserModel.query.filter(UserModel.email == user_data["email"]).first():
            abort(409, message="Your email is already registered")

        if BETA:
            result = BetaModel.query.filter(BetaModel.email == user_data["email"]).first()
            if result is None:
                abort(409, message="You do not have access to the beta")

        email_verification_token = str(uuid.uuid4())

        user = UserModel(
            email=user_data["email"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            password=bcrypt.hashpw(user_data["password"].encode('utf-8'), bcrypt.gensalt()),
            role="user",
            email_verification_token=email_verification_token,
            org_name=user_data["org_name"]
        )
        db.session.add(user)
        db.session.commit()

        org_joining_token = str(uuid.uuid4())

        # create the org
        admins = [user.id]
        org = OrgModel(
            org_owner=user.id,
            org_name=user_data["org_name"],
            admins=json.dumps(admins)
        )
        db.session.add(org)
        db.session.commit()

        user = UserModel.query.filter(UserModel.email == user_data["email"]).first()
        user.org_id = org.org_id
        db.session.commit()

        verification_link = url_for('users.VerifyEmail', token=email_verification_token, _external=True, _scheme='https')
        send_verification_email(user.email, verification_link)

        return {"message": "You have sucessfully registered. Please check your email to verify."}, 201


# If 404 is returned adjust page
@blp.route("/verify-email/<token>")
class VerifyEmail(MethodView):
    def get(self, token):
        user = UserModel.query.filter_by(email_verification_token=token).first_or_404()
        user.is_email_verified = True
        user.email_verification_token = None
        db.session.commit()
        return redirect(f'{config.Config.FRONTEND_URL}/email-verified?status=success')


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserLoginSchema)
    def post(self, user_data):
        """
        Login as a user and get access tokens.

        ---
        tags:
          - Authentication
        parameters:
          - in: body
            name: user
            description: User login details.
            required: true
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                password:
                  type: string
        responses:
          200:
            description: Return access and refresh tokens.
          401:
            description: Invalid credentials.
        """
        user = UserModel.query.filter(
            UserModel.email == user_data["email"]
        ).first()

        if user and bcrypt.checkpw(user_data["password"].encode('utf-8'),user.password.encode('utf-8')):
            if not user.is_email_verified:
                abort(403, message="You have not verified your account. Please check your email.")
            else:
                access_token = create_access_token(identity=user.id, fresh=True)
                refresh_token = create_refresh_token(identity=user.id)
                return {"access_token": access_token, "refresh_token": refresh_token}
        else:
            abort(401, message="Login details are incorrect")


@blp.route("/forgot-password")
class ForgotPassword(MethodView):
    def post(self):
        """
            Request a password reset.
            ---
            tags:
              - Authentication
            summary: Request a password reset
            parameters:
              - in: body
                name: body
                description: Email to send reset token to
                required: true
                schema:
                  type: object
                  required:
                    - email
                  properties:
                    email:
                      type: string
                      format: email  # Optional: Use 'format' to specify email validation
            responses:
              200:
                description: Forgotten password request sent sucessfully.
              400:
                description: Bad request - Missing or invalid email format
            """
        json_data = request.get_json()
        email = json_data.get('email')

        user = UserModel.query.filter_by(email=email).first()
        if not user:
            #To avoid numerating user list just return a 200 here
            return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200

        # Generate a password reset token and save it with the user's record
        user.reset_password_token = str(uuid.uuid4())
        db.session.commit()

        # reset_link = url_for('users.ResetPassword', token=user.reset_password_token, _external=True)
        reset_link = f"{config.Config.FRONTEND_URL}/reset-password/{user.reset_password_token}"

        # Send email with reset link (implement send_password_reset_email similar to send_verification_email)
        send_password_reset_email(user.email, reset_link)

        return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200


@blp.route("/reset-password/<token>")
class ResetPassword(MethodView):
    def post(self, token):
        """
           Reset Password with token
           ---
           tags:
                - Authentication
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
                   - new_password
                 properties:
                   new_password:
                     type: string
           responses:
             200:
               description: Password reset successful.
             400:
               description: Password reset failed.
           """
        json_data = request.get_json()
        new_password = json_data.get('password')

        user = UserModel.query.filter_by(reset_password_token=token).first()
        if not user:
            abort(404, description="Invalid or expired password reset token.")

        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.reset_password_token = None
        db.session.commit()

        return jsonify({"message": "Your password has been updated successfully."}), 200

@blp.route("/invite/<token>")
class InviteResetPassword(MethodView):
    def post(self, token):
        """
           Update a password from team invite
           ---
           tags:
                - Authentication
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
                   - new_password
                 properties:
                   new_password:
                     type: string
           responses:
             200:
               description: Password reset successful.
             400:
               description: Password reset failed.
           """
        json_data = request.get_json()
        new_password = json_data.get('password')

        user = UserModel.query.filter_by(reset_password_token=token).first()
        if not user:
            abort(404, description="Invalid or expired password reset token.")

        # Reset the user's password and clear the password reset token
        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.is_email_verified = True
        user.reset_password_token = None
        db.session.commit()

        return jsonify({"message": "Your password has been updated successfully."}), 200


@blp.route("/refresh")  # Working
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}


@blp.route("/logout")  # Working
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Succesfully logged out."}

@blp.route("/user/<int:user_id>/edit-role", methods=["PATCH"])
class EditUserRole(MethodView):
    @jwt_required()
    def patch(self, user_id):
        claims = get_jwt()
        current_user_role = claims.get("role")

        print("Current User Role:", current_user_role)  # Debugging

        # Check if the current user has sufficient permissions
        if current_user_role not in ["admin", "superadmin"]:
            print("Insufficient Permissions")
            abort(403, message="Insufficient permissions")

        # Fetch the user whose role needs to be edited
        user_to_edit = UserModel.query.get_or_404(user_id)

        # Check if the requested user exists
        if not user_to_edit:
            print("User not found")
            abort(404, message="User not found")

        # Extract the desired role from the request
        role = request.json.get("role")

        print("Desired Role:", role)  # Debugging

        # Check if the role is valid
        if role not in ["admin", "user"]:
            print("Invalid Role")
            abort(400, message="Invalid role")

        # Allow both Admin and Superadmin to upgrade a user to an admin
        if current_user_role in ["admin", "superadmin"] and role == "admin" and user_to_edit.role == "user":
            print(f"{current_user_role} Upgrade")  # Reflects the role performing the upgrade
            user_to_edit.role = "admin"
            try:
                db.session.commit()
                return {"message": "User role upgraded successfully"}
            except SQLAlchemyError:
                db.session.rollback()
                abort(500, message="Failed to update user's role")

        # Admin can only upgrade a user to an admin
        if current_user_role == "admin" and role == "admin" and user_to_edit.role == "user":
            print("Admin Upgrade")
            user_to_edit.role = "admin"
            try:
                db.session.commit()
                return {"message": "User role upgraded successfully"}
            except SQLAlchemyError:
                db.session.rollback()
                abort(500, message="Failed to update user's role")

        # If none of the conditions are met, return an error
        print("Invalid Operation or Permissions")
        abort(403, message="Insufficient permissions or invalid operation")


@blp.route('/mfa/setup', methods=['POST'])
@jwt_required()
def setup_mfa():
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)

    data = request.get_json()
    enable_mfa = data.get('enable', True)

    if enable_mfa:
        if not user.mfa_enabled:
            secret = pyotp.random_base32()
            user.mfa_secret = secret

            db.session.commit()

            totp = pyotp.TOTP(secret)
            otp_uri = totp.provisioning_uri(user.email, issuer_name="YourAppName")
            return jsonify({
                'message': 'MFA setup initiated. Scan the QR code with your app.',
                'otp_uri': otp_uri
            })
        else:
            return jsonify({'message': 'MFA is already set up.'}), 400
    else:
        if user.mfa_enabled:
            otp = data.get('otp')
            if otp is None or not pyotp.TOTP(user.mfa_secret).verify(otp):
                return jsonify({'message': 'Invalid or missing OTP.'}), 400
            user.mfa_enabled = False
            user.mfa_secret = None
            db.session.commit()
            return jsonify({'message': 'MFA has been disabled.'})
        else:
            return jsonify({'message': 'MFA is not enabled.'}), 400
        
@blp.route('/update_email', methods=['POST'])
@jwt_required()
def update_email():
    """
    Allows a user to update their email address after validating their password. Sends a verification email to the new address.
    ---
    tags:
      - Users
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
      - in: body
        name: body
        description: JSON object containing the new email and current user password.
        required: true
        schema:
          type: object
          properties:
            new_email:
              type: string
              format: email
            password:
              type: string
    responses:
      200:
        description: Verification email sent to new email address.
      400:
        description: Invalid data provided or email already in use.
      401:
        description: Incorrect password.
      403:
        description: Email verification required.
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)

    data = request.get_json()
    new_email = data.get('new_email')
    password = data.get('password')

    if UserModel.query.filter(UserModel.email == new_email).first():
        abort(400, message="Email already in use.")

    if not bcrypt.checkpw(password.encode('utf-8'),user.password.encode('utf-8')):
        abort(401, message="Incorrect password.")

    user.email = new_email
    user.is_email_verified = False
    user.email_verification_token = str(uuid.uuid4())
    db.session.commit()

    verification_link = url_for('users.VerifyEmail', token=user.email_verification_token, _external=True, _scheme='https')
    send_verification_email(new_email, verification_link)

    return jsonify({"message": "Verification email has been sent to your new email address."}), 200

@blp.route('/set_user_preference', methods=['POST'])
@jwt_required()
def set_user_preference():
    """
        Allows a user to update their preferences.
        ---
        tags:
          - Users
        parameters:
          - in: header
            name: Authorization
            description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
          - in: body
            name: body
            description: JSON object containing the new email and current user password.
            required: true
            schema:
              type: object
              properties:
                role:
                  type: string
                team:
                  type: string 
                infrastructure:
                  type: boolean
                social:
                  type: boolean
                wallet:
                  type: boolean
                defi:
                  type: boolean
                advisory:
                  type: boolean
                nft:
                  type: boolean
                learner:
                  type: boolean
                gaming:
                  type: boolean
                other:
                  type: string
                referred:
                  type: string
        responses:
          200:
            description: Verification email sent to new email address.
        """
    optional_params = {
        'role': None,
        'team': None,
        'infrastructure': False,
        'social': False,
        'wallet': False,
        'defi': False,
        'advisory': False,
        'nft': False,
        'learner': False,
        'gaming': False,
        'other': None,  # Default value for 'other' is None since it's a string
        'referred': None
    }

    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)

    params_dict = {}

    # Iterate through optional_params and update with request values
    for param, default_value in optional_params.items():
        if param in request.json:
            if isinstance(default_value, bool):
                # Convert to boolean value
                params_dict[param] = bool(request.json[param])
            else:
                # Use the value as is for non-boolean types
                params_dict[param] = request.json[param]
        else:
            # Use the default value for parameters not passed in request
            params_dict[param] = default_value

    user.preference = json.dumps(params_dict)
    db.session.commit()

    return jsonify({"message": "User preferences added"}), 200

@blp.route('/check_user_preferences', methods=['GET'])
@jwt_required()
def check_user_preferences():
    """
    Checks if the user's preference settings contain null values.
    ---
    tags:
      - Users
    parameters:
      - in: header
        name: Authorization
        description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the token
    responses:
      200:
        description: Preferences checked successfully. Returns which preferences are set to null.
      404:
        description: User not found.
      500:
        description: Error decoding preference data.
    """
    current_user_id = get_jwt_identity()
    user = UserModel.query.get(current_user_id)
    
    if not user:
        abort(404, message="User not found")

    try:
        # Load the preferences if they exist, otherwise use an empty dictionary
        preferences = json.loads(user.preference) if user.preference else {}
    except json.JSONDecodeError:
        abort(500, message="Error decoding preference data")

    # Check for null values in preferences
    null_preferences = {key: preferences.get(key) is None for key in [
        'role'
        'team'
        'infrastructure',
        'social',
        'wallet',
        'defi',
        'advisory',
        'nft',
        'learner',
        'gaming',
        'other'
        'referred'
    ]}

    return jsonify({
        "message": "Preference null check completed",
        "null_preferences": null_preferences
    }), 200


@blp.route("/change-password", methods=["POST"])
class ChangePassword(MethodView):
    @jwt_required()
    def post(self):
        """
        Change user's password.
        ---
        tags:
          - Authentication
        parameters:
          - in: header
            name: Authorization
            description: Type in the 'Value' input box below 'Bearer <JWT>', where JWT is the access token
          - in: body
            name: body
            description: Old password and new password
            required: true
            schema:
              type: object
              required:
                - old_password
                - new_password
              properties:
                old_password:
                  type: string
                  example: oldpassword123
                new_password:
                  type: string
                  example: newpassword123
        responses:
          200:
            description: Password changed successfully.
          401:
            description: Unauthorized - Incorrect old password.
          400:
            description: Bad request - if the new password does not meet criteria or old and new passwords are the same.
        """

        current_user_id = get_jwt_identity()
        user = UserModel.query.get_or_404(current_user_id)
        password_data = request.get_json()

        # Check old password
        if not bcrypt.checkpw(password_data["old_password"].encode('utf-8'), user.password.encode('utf-8')):
            abort(401, message="Old password is incorrect.")

        # Optionally, enforce password change policy or check if new password is different from old password
        if password_data["old_password"] == password_data["new_password"]:
            abort(400, message="New password must be different from old password.")

        # Update to new password
        user.password = bcrypt.hashpw(password_data["new_password"].encode('utf-8'), bcrypt.gensalt())
        db.session.commit()

        return jsonify({"message": "Password updated successfully."}), 200