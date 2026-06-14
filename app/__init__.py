# file: app/__init__.py

from pathlib import Path

from flask import Flask

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

    DB 모델은 app.models에 정의되어 있고,
    seed 실행 시 db.create_all()로 테이블을 생성합니다.
    """

    db.init_app(app)


def _register_template_helpers(app):
    """
    모든 템플릿에서 공통으로 사용할 값을 등록합니다.
    """

    from app.labs.registry import get_categories

    @app.context_processor
    def inject_sidebar_data():
        return {
            "lab_categories": get_categories(),
        }

def _register_blueprints(app):
    """
    URL 라우트를 Blueprint 단위로 등록합니다.
    """

    from app.blueprints.admin import admin_bp
    from app.blueprints.labs import labs_bp
    from app.blueprints.main import main_bp
    from app.blueprints.mock import mock_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(labs_bp)
    app.register_blueprint(mock_bp)


def _register_error_handlers(app):
    """
    기본 에러 페이지입니다.

    정식 HTML 템플릿은 Step 7에서 추가합니다.
    """

    @app.errorhandler(404)
    def not_found(error):
        return (
            "<h1>404</h1>"
            "<p>요청한 페이지를 찾을 수 없습니다.</p>"
            "<p><a href='/'>대시보드로 돌아가기</a></p>",
            404,
        )

    @app.errorhandler(500)
    def server_error(error):
        return (
            "<h1>500</h1>"
            "<p>서버 오류가 발생했습니다.</p>"
            "<p>로컬 개발 로그를 확인하세요.</p>",
            500,
        )