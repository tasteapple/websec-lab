# file: app/blueprints/mock.py

from flask import Blueprint, jsonify


mock_bp = Blueprint("mock", __name__, url_prefix="/mock")


@mock_bp.get("/public/status")
def public_status():
    """
    SSRF 실습에서 허용 가능한 공개 mock endpoint입니다.
    """

    return jsonify(
        {
            "scope": "public",
            "service": "status",
            "message": "public mock service is reachable",
        }
    )


@mock_bp.get("/internal/profile")
def internal_profile():
    """
    내부 서비스처럼 보이는 로컬 mock endpoint입니다.

    실제 내부망이나 클라우드 메타데이터에 접근하지 않습니다.
    """

    return jsonify(
        {
            "scope": "internal",
            "service": "profile",
            "username": "training-user",
            "role": "customer",
        }
    )


@mock_bp.get("/internal/metadata")
def internal_metadata():
    """
    클라우드 metadata endpoint처럼 보이는 학습용 mock입니다.

    실제 credential, token, 시스템 정보는 포함하지 않습니다.
    """

    return jsonify(
        {
            "scope": "internal",
            "service": "metadata",
            "instance_id": "local-training-instance",
            "environment": "local-only",
            "note": "mock metadata for SSRF training",
        }
    )


@mock_bp.get("/internal/admin-note")
def internal_admin_note():
    """
    관리자 내부 메모처럼 보이는 학습용 mock입니다.

    실제 비밀값을 넣지 않고 접근 제어 개념 설명용 데이터만 반환합니다.
    """

    return jsonify(
        {
            "scope": "internal",
            "service": "admin-note",
            "message": "this mock endpoint represents data that should not be reachable through user-controlled fetch",
        }
    )