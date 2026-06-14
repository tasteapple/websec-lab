# file: app/blueprints/labs.py

from flask import Blueprint, abort, render_template, request

from app.labs.file_upload import get_lab as get_file_upload_lab
from app.labs.file_upload import run_level as run_file_upload_level
from app.labs.registry import get_category
from app.labs.sqli import get_lab as get_sqli_lab
from app.labs.sqli import run_level as run_sqli_level
from app.labs.xss import get_lab as get_xss_lab
from app.labs.xss import run_level as run_xss_level
from app.labs.ssrf import get_lab as get_ssrf_lab
from app.labs.ssrf import run_level as run_ssrf_level
from app.labs.ssti import get_lab as get_ssti_lab
from app.labs.ssti import run_level as run_ssti_level


labs_bp = Blueprint("labs", __name__, url_prefix="/labs")


LAB_RUNTIME = {
    "sqli": {
        "get_lab": get_sqli_lab,
        "run_level": run_sqli_level,
    },
    "xss": {
        "get_lab": get_xss_lab,
        "run_level": run_xss_level,
    },
    "file-upload": {
        "get_lab": get_file_upload_lab,
        "run_level": run_file_upload_level,
    },
    "ssrf": {
        "get_lab": get_ssrf_lab,
        "run_level": run_ssrf_level,
    },
    "ssti": {
        "get_lab": get_ssti_lab,
        "run_level": run_ssti_level,
    }
}


@labs_bp.get("/<category_slug>")
def category(category_slug):
    """
    카테고리별 Lab 목록 페이지입니다.
    """

    category_data = get_category(category_slug)
    if category_data is None:
        abort(404)

    return render_template(
        "labs/category.html",
        active_page="labs",
        active_category=category_slug,
        category=category_data,
    )


@labs_bp.route("/<category_slug>/<lab_id>/level/<int:level>", methods=["GET", "POST"])
def lab_level(category_slug, lab_id, level):
    """
    특정 Lab의 특정 Level 페이지입니다.
    """

    category_data = get_category(category_slug)
    if category_data is None:
        abort(404)

    runtime = LAB_RUNTIME.get(category_slug)
    if runtime is None:
        abort(404)

    lab = runtime["get_lab"](lab_id)
    if lab is None:
        abort(404)

    level_data = lab.get_level(level)
    if level_data is None:
        abort(404)

    result = None
    has_file_upload = any(
        field.field_type == "file"
        for field in level_data.form_fields
    )

    if request.method == "POST":
        result = runtime["run_level"](
            lab_id,
            level,
            request.form,
            request.files,
        )

    levels = [
        {
            "level": item_level,
        }
        for item_level in sorted(lab.levels.keys())
    ]

    return render_template(
        "labs/lab_level.html",
        active_page="labs",
        active_category=category_slug,
        category=category_data,
        category_slug=category_slug,
        lab=lab,
        lab_id=lab_id,
        level_data=level_data,
        current_level=level,
        levels=levels,
        result=result,
        has_file_upload=has_file_upload,
    )