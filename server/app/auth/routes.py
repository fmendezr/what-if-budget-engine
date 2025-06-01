from datetime import datetime, timezone
from flask import request, jsonify
from sqlalchemy import select
from pydantic import ValidationError
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from app.extensions import db, jwt
from app.models import User, TokenBlocklist
from app.security import pwd_context
from app.auth import auth_bp
from app.auth.schemas import LoginModel, SignupModel

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        payload = request.get_json(force=True)
        data = LoginModel(payload)
    except (TypeError, ValidationError) as err:
        return jsonify({"error": "invalid input", 'detail': err.errors()}), 422
    
    stmt = select(User).where((User.username == data.username))
    user = db.session.scalar(stmt)

    if user is None or not user.verify_password(data.password):
        return jsonify({"error": "Incorrect Credentials"}), 401
    
    access_token = create_access_token(fresh=True, identity=data.username)
    refresh_token = create_refresh_token(identity=data.username)

    return jsonify(access_token=access_token, refresh_token=refresh_token)

@auth_bp.route("/logout", methods=["DELETE"])
@jwt_required()
def modify_token():
    token = get_jwt()
    jti = token["jti"]
    ttype = token["type"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
    db.session.commit()
    return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    return jsonify(access_token=access_token)

@auth_bp.route("/signup", methods=["POST"])
def signup():
    try:
        payload = request.get_json(force=True)
        data = SignupModel.model_validate(payload)
    except (TypeError, ValidationError) as err:
        return jsonify({'errors': 'Invalid input', 'detail': err.errors()}), 422

    stmt = select(User).where((data.username == User.username) | (data.email == User.email))
    existing_user = db.session.scalar(stmt)

    if existing_user:
        conflicts = []
        if (existing_user.username == data.username):
            conflicts.append('username')
        if (existing_user.email == data.email):
            conflicts.append('email')
        message = ', '.join(conflicts) + ' already exists' if len(conflicts) == 1 else ' already exist'
        return jsonify({'error': message}), 409
    
    new_user = User(username=data.username, email=data.email)
    new_user.set_password(data.password)

    try:
        db.session.commit(new_user)
    except:
        db.session.rollback()
        return jsonify({'error': 'User already exists'})
    
    return jsonify({'message': "Signup successful"})
