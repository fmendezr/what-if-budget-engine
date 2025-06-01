from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from sqlalchemy import select

from app.models import User, TokenBlocklist

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def _json_error(message: str, status: int):
    return jsonify({"msg": message}), status 

def init_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)
    jwt.init_app(app)

    # gloabl JWT error handlers 
    # Callback function to check if a JWT exists in the database blocklist
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

        return token is not None
    
    @jwt.unauthorized_loader
    def _missing_token(reason):
        return _json_error("Missing or invalid token", 401)
    
    @jwt.invalid_token_loader
    def _bad_token(reason):
        return _json_error("Token in malformed", 422)
    
    @jwt.expired_token_loader
    def _expired_token(jwt_header, jwt_payload):
        return _json_error("Token is expired", 401)
    
    @jwt.needs_fresh_token_loader
    def _needs_fresh(jwt_header, jwt_payload):
        return _json_error("Fresh token is requiered", 401)
    
    @jwt.revoked_token_loader
    def _revoked_token(jwt_header, jwt_payload):
        return _json_error("Token has been revoked", 401)
    
    @jwt.token_verification_failed_loader
    def _claims_failed(jwt_header, jwt_payload):
        return _json_error("Token failed custom claims checks", 400)
    
    # automatic user <-> identity hooks
    @jwt.user_identity_loader
    def _user_to_identity(user):
        return user.username if hasattr(user, "username") else str(user)
    
    @jwt.user_lookup_loader
    def _indentity_to_user(jwt_header, jwt_payload):
        identity = jwt_payload['sub']
        stmt = select(User).where(User.username == identity)
        return db.session.scalar(stmt)
    
    @jwt.user_lookup_error_loader
    def _user_not_found(jwt_header, jwt_payload):
        return _json_error("User no longer exists", 404)
