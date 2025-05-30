from flask import Flask
from app.config import Config
from app.extensions import init_extensions
from app.auth import auth_bp
from app.budget import budget_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    init_extensions(app)

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(budget_bp, url_prefix="/api/budget")

    return app