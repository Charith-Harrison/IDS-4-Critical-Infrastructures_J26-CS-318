"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Web Application Package Initialization
"""

import os
import yaml
from flask import Flask


def create_app(config_path: str = "config/default.yaml") -> Flask:
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(app_dir)

    template_dir = os.path.join(app_dir, "templates")
    static_dir = os.path.join(app_dir, "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )

    if not os.path.isabs(config_path):
        config_path = os.path.join(project_root, config_path)

    with open(config_path, "r", encoding="utf-8") as f:
        app.config["APP_CONFIG"] = yaml.safe_load(f)
    app.config["PROJECT_ROOT"] = project_root

    # Maximum file upload size: 200 MB
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
    app.config["UPLOAD_FOLDER"] = os.path.join(project_root, "uploads")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app
