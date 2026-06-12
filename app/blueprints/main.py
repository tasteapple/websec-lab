# file: app/blueprints/main.py

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request

from app.labs.registry import (
    get_categories,
    get_total_lab_count,
    get_total_level_count,
)


main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def dashboard():
    """
    대시보드입니다.

    전체 카테고리, Lab 개수, Level 개수를 보여줍니다.
    """

    stats = {
        "category_count": len(get_categories()),
        "lab_count": get_total_lab_count(),
        "level_count": get_total_level_count(),
        "external_network_enabled": current_app.config["EXTERNAL_NETWORK_ENABLED"],
    }

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        active_category=None,
        stats=stats,
    )


@main_bp.get("/health")
def health():
    """
    서버 상태 확인 endpoint입니다.

    브라우저에서 열면 HTML 페이지를 보여주고,
    JSON을 선호하는 클라이언트에는 JSON을 반환합니다.
    """

    health_data = {
        "status": "ok",
        "app": "websec-local-lab",
        "external_network_enabled": current_app.config["EXTERNAL_NETWORK_ENABLED"],
        "upload_dir": str(current_app.config["UPLOAD_DIR"]),
        "cache_dir": str(current_app.config["CACHE_DIR"]),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    wants_json = (
        request.accept_mimetypes["application/json"]
        >= request.accept_mimetypes["text/html"]
    )

    if wants_json:
        return jsonify(health_data)

    return render_template(
        "health.html",
        active_page="health",
        active_category=None,
        health=health_data,
    )