# file: app/__init__.py

from pathlib import Path

from flask import Flask, render_template

from config import Config
from app.extensions import db


def create_app(config_class=Config):
    """
    Flask 애플리케이션 팩토리입니다.

    앱을 전역에서 바로 만들지 않고 함수로 생성하면,
    테스트 환경과 개발 환경 설정을 쉽게 분리할 수 있습니다.
    """

    app = Flask(
        __name__,
        instance_relative_config=True,
    )

    app.config.from_object(config_class)

    _ensure_local_directories(app)
    _init_extensions(app)
    _register_blueprints(app)
    _register_template_helpers(app)
    _register_error_handlers(app)

    return app


def _ensure_local_directories(app):
    """
    로컬 실행에 필요한 instance 하위 디렉터리를 만듭니다.

    업로드와 캐시 실습은 반드시 프로젝트 내부의 제한된 위치만 사용합니다.
    """

    upload_dir = Path(app.config["UPLOAD_DIR"])
    cache_dir = Path(app.config["CACHE_DIR"])

    upload_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)


def _init_extensions(app):
    """
    Flask 확장 기능을 초기화합니다.
    """

    db.init_app(app)


def _register_blueprints(app):
    """
    URL 라우트를 Blueprint 단위로 등록합니다.
    """

    from app.blueprints.admin import admin_bp
    from app.blueprints.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)


def _register_template_helpers(app):
    """
    모든 템플릿에서 공통으로 사용할 값을 등록합니다.

    사이드바는 모든 페이지에 필요하므로 lab_categories를 전역으로 제공합니다.
    """

    from app.labs.registry import get_categories

    @app.context_processor
    def inject_sidebar_data():
        return {
            "lab_categories": get_categories(),
        }


def _register_error_handlers(app):
    """
    기본 에러 페이지입니다.
    """

    @app.errorhandler(404)
    def not_found(error):
        return (
            render_template(
                "errors/404.html",
                active_page=None,
                active_category=None,
            ),
            404,
        )

    @app.errorhandler(500)
    def server_error(error):
        return (
            render_template(
                "errors/500.html",
                active_page=None,
                active_category=None,
            ),
            500,
        )