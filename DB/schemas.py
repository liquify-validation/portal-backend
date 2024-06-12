from marshmallow import Schema, fields, EXCLUDE

class UserSchema(Schema):
    id = fields.Str(dump_only=True) 
    email = fields.Str(required=True)
    first_name = fields.Str(required=True)  
    last_name = fields.Str(required=True)   
    role = fields.Str(missing="user")
    password = fields.Str(required=True, load_only=True)
    org_name = fields.Str(required=False)

class UserLoginSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)

class GoogleUserSchema(Schema):
    email = fields.Email(required=True)
    first_name = fields.Str(required=True, data_key="given_name")
    last_name = fields.Str(required=True, data_key="family_name")
    is_email_verified = fields.Boolean(required=True, data_key="verified_email", dump_default=True)

    class Meta:
        unknown = EXCLUDE

class ChainsSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    date_added = fields.DateTime(dump_only=True)

class APIKeySchema(Schema):
    id = fields.Int(dump_only=True)
    api_name = fields.Str(required=True)
    chain_name = fields.Str(required=True)  
    api_key = fields.Str(dump_only=True)
    date_created = fields.DateTime(dump_only=True)
    limit = fields.Int(required=False)
    user_id = fields.Int(dump_only=True) 

class PasswordChangeSchema(Schema):
    old_password = fields.String(required=True)
    new_password = fields.String(required=True)