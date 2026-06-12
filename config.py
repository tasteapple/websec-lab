# file: config.py

from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    """
    Flask 앱의 공통 설정입니다.

    이 프로젝트에는 교육용 취약 코드가 포함될 예정이므로,
    기본 실행 범위와 파일 저장 경로를 명확히 제한합니다.
    """

    # 로컬 개발용 secret key입니다.
    # 실제 서비스에서는 반드시 환경변수로 안전하게 관리해야 합니다.
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "local-dev-secret-key-change-me"
    )

    # SQLite DB는 instance 디렉터리 아래에만 생성합니다.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{INSTANCE_DIR / 'app.sqlite3'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 업로드 파일은 프로젝트 내부의 제한된 디렉터리에만 저장합니다.
    UPLOAD_DIR = INSTANCE_DIR / "uploads"

    # 캐시 실습도 실제 외부 캐시 서버 대신 로컬 디렉터리 또는 메모리 mock을 사용합니다.
    CACHE_DIR = INSTANCE_DIR / "cache"

    # 너무 큰 파일 업로드를 막기 위한 기본 제한입니다.
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024

    # 교육용 앱이므로 기본적으로 외부 네트워크 호출은 비활성화합니다.
    EXTERNAL_NETWORK_ENABLED = False

    # SSRF 실습에서 사용할 수 있는 대상은 로컬 mock endpoint로 제한합니다.
    SSRF_ALLOWED_PREFIX = "http://127.0.0.1:5000/mock/"

    # 기본 실행 호스트입니다.
    LOCAL_ONLY_HOST = "127.0.0.1"